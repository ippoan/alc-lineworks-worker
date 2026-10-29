//! SQL を流す 1 か所 (`PgClient::tenant_tx` + `query_typed` 系だけ。名前付き prepared statement は使わない)。
//!
//! 送信の口には tenant のヘッダーが無い。宛先の行 id から tenant を引くのは、rust-alc-api と同じ SECURITY DEFINER の
//! 関数 `alc_api.lookup_lineworks_channel_for_send` (migration 129) と `alc_api.lookup_notify_recipient_for_send` (130)。
//! `PgClient` にはテナントを設定しない transaction の口が無いので、`tenant_tx(Uuid::nil(), ..)` の中でこの関数だけを呼ぶ
//! (ohishi-exp/rust-leave-worker の `pg::resolve_mailbox` と同じ型。nil UUID はどの tenant にも当たらない値)。
//! 引いた tenant で、改めて `tenant_tx` を張り、bot_configs の行を読む (RLS に加えて `WHERE tenant_id` でも絞る)。
//!
//! **bot_configs の `private_key_encrypted` は読まない** (Private Key は Secrets Store の `LINEWORKS_PRIVATE_KEY` だけ)。

use alc_worker_db::PgClient;
use tokio_postgres::types::Type;
use tokio_postgres::Error;
use uuid::Uuid;

pub mod sql {
    /// channel 行 id → (tenant, bot_config, LINE WORKS の channel id)。active = false の行も返る (rust と同じ)
    pub const CHANNEL_FOR_SEND: &str = "SELECT tenant_id, bot_config_id, channel_id \
         FROM alc_api.lookup_lineworks_channel_for_send($1)";

    /// recipient 行 id → (tenant, provider, LINE WORKS の user id, enabled)
    pub const RECIPIENT_FOR_SEND: &str = "SELECT tenant_id, provider, lineworks_user_id, enabled \
         FROM alc_api.lookup_notify_recipient_for_send($1)";

    /// channel 宛: channel 行が指す bot の設定 (rust の `get_config_with_secrets` と同じく provider・enabled は見ない)
    pub const BOT_CONFIG_BY_ID: &str =
        "SELECT client_id, client_secret_encrypted, service_account, bot_id \
         FROM alc_api.bot_configs WHERE tenant_id = $1 AND id = $2";

    /// recipient 宛 (bot 指定): 指定の bot が、その tenant の有効な LINE WORKS の bot のときだけ返る
    pub const LINEWORKS_BOT_CONFIG_BY_ID: &str =
        "SELECT client_id, client_secret_encrypted, service_account, bot_id \
         FROM alc_api.bot_configs WHERE tenant_id = $1 AND id = $2 AND provider = 'lineworks' AND enabled";

    /// recipient 宛: tenant の有効な LINE WORKS の bot のうち名前の順で最初の 1 つ
    /// (rust の `pick_lineworks_bot_config_id` = `list_configs` の `ORDER BY name` の最初。同じ名前は id の順)
    pub const BOT_CONFIG_FOR_TENANT: &str =
        "SELECT client_id, client_secret_encrypted, service_account, bot_id \
         FROM alc_api.bot_configs WHERE tenant_id = $1 AND provider = 'lineworks' AND enabled \
         ORDER BY name, id LIMIT 1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRow {
    pub tenant_id: Uuid,
    pub bot_config_id: Uuid,
    pub channel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRow {
    pub tenant_id: Uuid,
    pub provider: String,
    pub lineworks_user_id: Option<String>,
    pub enabled: bool,
}

/// bot の設定 (client_secret は暗号文のまま)
#[derive(Clone, PartialEq, Eq)]
pub struct BotConfigRow {
    pub client_id: String,
    pub client_secret_encrypted: String,
    pub service_account: String,
    pub bot_id: String,
}

type BotTuple = (String, String, String, String);

fn bot_row(
    (client_id, client_secret_encrypted, service_account, bot_id): BotTuple,
) -> BotConfigRow {
    BotConfigRow {
        client_id,
        client_secret_encrypted,
        service_account,
        bot_id,
    }
}

pub async fn channel_for_send(pg: &mut PgClient, id: Uuid) -> Result<Option<ChannelRow>, Error> {
    let row = pg
        .tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_opt(sql::CHANNEL_FOR_SEND, &[(&id, Type::UUID)])
                    .await?;
                Ok(row.map(|r| {
                    (
                        r.get::<_, Uuid>(0),
                        r.get::<_, Uuid>(1),
                        r.get::<_, String>(2),
                    )
                }))
            })
        })
        .await?;
    Ok(
        row.map(|(tenant_id, bot_config_id, channel_id)| ChannelRow {
            tenant_id,
            bot_config_id,
            channel_id,
        }),
    )
}

pub async fn recipient_for_send(
    pg: &mut PgClient,
    id: Uuid,
) -> Result<Option<RecipientRow>, Error> {
    let row = pg
        .tenant_tx(Uuid::nil(), move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_opt(sql::RECIPIENT_FOR_SEND, &[(&id, Type::UUID)])
                    .await?;
                Ok(row.map(|r| {
                    (
                        r.get::<_, Uuid>(0),
                        r.get::<_, String>(1),
                        r.get::<_, Option<String>>(2),
                        r.get::<_, bool>(3),
                    )
                }))
            })
        })
        .await?;
    Ok(row.map(
        |(tenant_id, provider, lineworks_user_id, enabled)| RecipientRow {
            tenant_id,
            provider,
            lineworks_user_id,
            enabled,
        },
    ))
}

fn bot_tuple(r: &tokio_postgres::Row) -> BotTuple {
    (r.get(0), r.get(1), r.get(2), r.get(3))
}

pub async fn bot_config_by_id(
    pg: &mut PgClient,
    tenant_id: Uuid,
    bot_config_id: Uuid,
) -> Result<Option<BotConfigRow>, Error> {
    let row = pg
        .tenant_tx(tenant_id, move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_opt(
                        sql::BOT_CONFIG_BY_ID,
                        &[(&tenant_id, Type::UUID), (&bot_config_id, Type::UUID)],
                    )
                    .await?;
                Ok(row.as_ref().map(bot_tuple))
            })
        })
        .await?;
    Ok(row.map(bot_row))
}

pub async fn bot_config_for_tenant(
    pg: &mut PgClient,
    tenant_id: Uuid,
) -> Result<Option<BotConfigRow>, Error> {
    let row = pg
        .tenant_tx(tenant_id, move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_opt(sql::BOT_CONFIG_FOR_TENANT, &[(&tenant_id, Type::UUID)])
                    .await?;
                Ok(row.as_ref().map(bot_tuple))
            })
        })
        .await?;
    Ok(row.map(bot_row))
}

pub async fn lineworks_bot_config_by_id(
    pg: &mut PgClient,
    tenant_id: Uuid,
    bot_config_id: Uuid,
) -> Result<Option<BotConfigRow>, Error> {
    let row = pg
        .tenant_tx(tenant_id, move |tx| {
            Box::pin(async move {
                let row = tx
                    .query_typed_opt(
                        sql::LINEWORKS_BOT_CONFIG_BY_ID,
                        &[(&tenant_id, Type::UUID), (&bot_config_id, Type::UUID)],
                    )
                    .await?;
                Ok(row.as_ref().map(bot_tuple))
            })
        })
        .await?;
    Ok(row.map(bot_row))
}

// ---------- Bot 設定の管理 (rust-alc-api の /api/admin/bot/configs から移した。Refs ippoan/rust-alc-api#680) ----------
//
// すべてその会社の transaction で、WHERE / VALUES に tenant_id を明示する (移植元の一覧・更新・削除は WHERE に
// tenant_id が無く RLS 任せだった)。秘密値は暗号文で受けて保存するだけ (暗号化は呼び手の [`crate::bot_admin`])。

pub mod admin_sql {
    /// 一覧で返す列 (秘密値の列は読まない)
    macro_rules! bot_admin_columns {
        () => {
            "id, provider, name, client_id, service_account, bot_id, enabled, created_at, updated_at"
        };
    }

    pub const LIST: &str = concat!(
        "SELECT ",
        bot_admin_columns!(),
        " FROM alc_api.bot_configs WHERE tenant_id = $1 ORDER BY name, id"
    );

    pub const INSERT: &str = concat!(
        "INSERT INTO alc_api.bot_configs \
         (tenant_id, provider, name, client_id, client_secret_encrypted, service_account, bot_id, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING ",
        bot_admin_columns!()
    );

    pub const UPDATE: &str = concat!(
        "UPDATE alc_api.bot_configs SET provider = $3, name = $4, client_id = $5, \
         service_account = $6, bot_id = $7, enabled = $8, updated_at = NOW() \
         WHERE tenant_id = $1 AND id = $2 RETURNING ",
        bot_admin_columns!()
    );

    pub const UPDATE_CLIENT_SECRET: &str = "UPDATE alc_api.bot_configs \
         SET client_secret_encrypted = $3 WHERE tenant_id = $1 AND id = $2";

    pub const UPDATE_BOT_SECRET: &str = "UPDATE alc_api.bot_configs \
         SET bot_secret_encrypted = $3 WHERE tenant_id = $1 AND id = $2";

    pub const DELETE: &str = "DELETE FROM alc_api.bot_configs WHERE tenant_id = $1 AND id = $2";

    /// export (開発者だけ。開発者の判定は auth-worker): 会社の 1 行 (tenants は RLS の無い表。id で絞る)
    pub const EXPORT_TENANT: &str =
        "SELECT id, name, slug, email_domain, created_at FROM alc_api.tenants WHERE id = $1";

    /// export: 会社の Bot 設定の全部の列 (秘密値は暗号文のまま。名前の順。移植元は RLS 任せで WHERE が無かった)
    pub const EXPORT_CONFIGS: &str =
        "SELECT id, tenant_id, provider, name, client_id, client_secret_encrypted, \
         service_account, bot_id, enabled, bot_secret_encrypted, created_at, updated_at \
         FROM alc_api.bot_configs WHERE tenant_id = $1 ORDER BY name, id";
}

/// export の会社の 1 行 (移植元の `TenantInfoForExport` と同じ形)
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TenantExport {
    pub id: Uuid,
    pub name: String,
    pub slug: Option<String>,
    pub email_domain: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// export の Bot 設定の 1 行 (移植元の `BotConfigExportRow` と同じ形。秘密値は暗号文のまま)
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BotExportRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub client_secret_encrypted: String,
    pub service_account: String,
    pub bot_id: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_secret_encrypted: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// export の材料 (会社と、その Bot 設定)
#[derive(Debug, Clone, PartialEq)]
pub struct BotExport {
    pub tenant: TenantExport,
    pub configs: Vec<BotExportRow>,
}

impl alc_worker_db::TxOutput for BotExport {}

/// export の材料を、その会社の 1 つの transaction で読む。会社が無ければ `None`
pub async fn bot_admin_export(
    pg: &mut PgClient,
    tenant_id: Uuid,
) -> Result<Option<BotExport>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let params: [(&(dyn tokio_postgres::types::ToSql + Sync), Type); 1] =
                [(&tenant_id, Type::UUID)];
            let Some(t) = tx
                .query_typed_opt(admin_sql::EXPORT_TENANT, &params)
                .await?
            else {
                return Ok(None);
            };
            let tenant = TenantExport {
                id: t.get(0),
                name: t.get(1),
                slug: t.get(2),
                email_domain: t.get(3),
                created_at: t.get(4),
            };
            let rows = tx.query_typed(admin_sql::EXPORT_CONFIGS, &params).await?;
            let configs = rows
                .iter()
                .map(|r| BotExportRow {
                    id: r.get(0),
                    tenant_id: r.get(1),
                    provider: r.get(2),
                    name: r.get(3),
                    client_id: r.get(4),
                    client_secret_encrypted: r.get(5),
                    service_account: r.get(6),
                    bot_id: r.get(7),
                    enabled: r.get(8),
                    bot_secret_encrypted: r.get(9),
                    created_at: r.get(10),
                    updated_at: r.get(11),
                })
                .collect();
            Ok(Some(BotExport { tenant, configs }))
        })
    })
    .await
}

/// Bot 設定の 1 行 (移植元の `BotConfigResponse` と同じ形。秘密値は持たない)
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BotAdminRow {
    pub id: Uuid,
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub service_account: String,
    pub bot_id: String,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl alc_worker_db::TxOutput for BotAdminRow {}

fn bot_admin_row(r: &tokio_postgres::Row) -> BotAdminRow {
    BotAdminRow {
        id: r.get(0),
        provider: r.get(1),
        name: r.get(2),
        client_id: r.get(3),
        service_account: r.get(4),
        bot_id: r.get(5),
        enabled: r.get(6),
        created_at: r.get(7),
        updated_at: r.get(8),
    }
}

/// Bot 設定の保存の入力。`id` が在れば更新、無ければ作成。秘密値は暗号文 (`None` なら変えない)
#[derive(Debug, Clone, PartialEq)]
pub struct BotAdminInput {
    pub id: Option<Uuid>,
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub service_account: String,
    pub bot_id: String,
    pub enabled: bool,
    pub client_secret_encrypted: Option<String>,
    pub bot_secret_encrypted: Option<String>,
}

pub async fn bot_admin_list(pg: &mut PgClient, tenant_id: Uuid) -> Result<Vec<BotAdminRow>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let rows = tx
                .query_typed(admin_sql::LIST, &[(&tenant_id, Type::UUID)])
                .await?;
            Ok(rows.iter().map(bot_admin_row).collect())
        })
    })
    .await
}

/// 作成 / 更新と秘密値の差し替えを 1 つの transaction で。更新の対象がその会社に無ければ `None`
pub async fn bot_admin_save(
    pg: &mut PgClient,
    tenant_id: Uuid,
    b: BotAdminInput,
) -> Result<Option<BotAdminRow>, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            let row = match b.id {
                Some(id) => {
                    let Some(row) = tx
                        .query_typed_opt(
                            admin_sql::UPDATE,
                            &[
                                (&tenant_id, Type::UUID),
                                (&id, Type::UUID),
                                (&b.provider, Type::TEXT),
                                (&b.name, Type::TEXT),
                                (&b.client_id, Type::TEXT),
                                (&b.service_account, Type::TEXT),
                                (&b.bot_id, Type::TEXT),
                                (&b.enabled, Type::BOOL),
                            ],
                        )
                        .await?
                    else {
                        return Ok(None);
                    };
                    if let Some(secret) = &b.client_secret_encrypted {
                        tx.execute_typed(
                            admin_sql::UPDATE_CLIENT_SECRET,
                            &[
                                (&tenant_id, Type::UUID),
                                (&id, Type::UUID),
                                (secret, Type::TEXT),
                            ],
                        )
                        .await?;
                    }
                    row
                }
                None => {
                    // 移植元と同じく、作成で client secret が無ければ空文字の暗号文 (呼び手が作る) を入れる
                    let secret = b.client_secret_encrypted.clone().unwrap_or_default();
                    tx.query_typed_one(
                        admin_sql::INSERT,
                        &[
                            (&tenant_id, Type::UUID),
                            (&b.provider, Type::TEXT),
                            (&b.name, Type::TEXT),
                            (&b.client_id, Type::TEXT),
                            (&secret, Type::TEXT),
                            (&b.service_account, Type::TEXT),
                            (&b.bot_id, Type::TEXT),
                            (&b.enabled, Type::BOOL),
                        ],
                    )
                    .await?
                }
            };
            let saved = bot_admin_row(&row);
            if let Some(secret) = &b.bot_secret_encrypted {
                tx.execute_typed(
                    admin_sql::UPDATE_BOT_SECRET,
                    &[
                        (&tenant_id, Type::UUID),
                        (&saved.id, Type::UUID),
                        (secret, Type::TEXT),
                    ],
                )
                .await?;
            }
            Ok(Some(saved))
        })
    })
    .await
}

/// その会社の Bot 設定を消す。消えた行数 (無い・他社は 0)
pub async fn bot_admin_delete(pg: &mut PgClient, tenant_id: Uuid, id: Uuid) -> Result<u64, Error> {
    pg.tenant_tx(tenant_id, move |tx| {
        Box::pin(async move {
            tx.execute_typed(
                admin_sql::DELETE,
                &[(&tenant_id, Type::UUID), (&id, Type::UUID)],
            )
            .await
        })
    })
    .await
}
