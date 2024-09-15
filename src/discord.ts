import { Hono } from 'hono'
import * as jose from 'jose'
import { loadKeyPair, ErrMessage, Bindings, hash_func, discord_guild_role_whitelist } from './utils'
import * as discord_api from './api/discord'

const hono_discord = new Hono<{ Bindings: Bindings }>()

hono_discord.get('/callback', async (c) => {
    //V receive code and state(oidc_state_hash)
    //V 跟 dc 換 access token
    //V 檢查 oidc_state_hash 有沒有存在 oidc_req_tmp
    //V 檢查 oidc_state_hash -> client_id 對應到的 scope, 主要檢查 dcmg_<server_id>_<role_id> 有沒有符合
    //V 如果 scope 滿足,跳轉到 oidc_state_hash -> redirect_uri, 帶上 oidc_state_hash -> code 跟 oidc_state_hash -> oidc_state
    const code = c.req.query('code')
    const oidc_state_hash = c.req.query('state')

    if(code==undefined||code==null||oidc_state_hash==undefined||oidc_state_hash==null){
        return c.json(new ErrMessage("discord callback error","state and code are required").dict(), 400)
    }

    let { results } = await c.env.DB.prepare(
        "SELECT oidc_req_tmp.oidc_state_hash, oidc_req_tmp.oidc_state, oidc_req_tmp.client_id, oidc_req_tmp.redirect_uri, oidc_req_tmp.code, oidc_req_tmp.datr, oidc_req_tmp.created_at, oidc_client.scope FROM oidc_req_tmp INNER JOIN oidc_client ON oidc_req_tmp.client_id=oidc_client.client_id WHERE oidc_req_tmp.oidc_state_hash = ?",
      )
    .bind(oidc_state_hash)
    .all();
    
    //oidc_state_hash not found in oidc_req_tmp
    if(results.length == 0){
        return c.json(new ErrMessage("discord callback error","state not found").dict(), 401)
    }

    //Discord Access Token Response
    const discord_token_res:any = await discord_api.oauth2_token(c.env.DC_CLIENT_ID, c.env.DC_CLIENT_SECRET, c.env.DC_REDIRECT_URI, code)
    if(discord_token_res===null){
        await c.env.DB.prepare(
            "DELETE FROM oidc_req_tmp WHERE oidc_state_hash=?;",
        )
        .bind(oidc_state_hash)
        .all();
        return c.redirect(`${results[0].redirect_uri}?${new ErrMessage("discord callback error","discord access token response is null").params()}`)
    }

    //verify user's current discord guilds and roles
    let passed = await discord_api.discord_user_permission_verify(discord_token_res["access_token"],results[0].scope as string)

    //DENY=================

    if(!passed){
        await c.env.DB.prepare(
            "DELETE FROM oidc_req_tmp WHERE oidc_state_hash=?;",
        )
        .bind(oidc_state_hash)
        .all();
        return c.redirect(`${results[0].redirect_uri}?${new ErrMessage("discord callback error","deny").params()}`)
    }

    //PASSED=================

    //save Discord Access Token Response
    await c.env.DB.prepare(
        "UPDATE oidc_req_tmp SET datr=? WHERE oidc_state_hash=?;",
    )
    .bind(JSON.stringify(discord_token_res),oidc_state_hash)
    .all();

    //passed
    const params = new URLSearchParams({
        'code': (results[0].code as string),
        'state': (results[0].oidc_state as string)
    }).toString()
    return c.redirect(`${results[0].redirect_uri}?${params}`)
})

export default hono_discord