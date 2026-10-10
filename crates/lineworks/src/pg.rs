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
