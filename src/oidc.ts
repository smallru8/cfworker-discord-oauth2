import { Hono } from 'hono'
import * as jose from 'jose'
import * as basic_auth from 'basic-auth'
import { loadKeyPair, ErrMessage, Bindings, hash_func, discord_guild_role_whitelist } from './utils'
import * as discord_api from './api/discord'
import hono_well_known from './well_known'

const hono_oidc = new Hono<{ Bindings: Bindings }>()

/*==========================================*/
// OAUTH2
/**
 * redirect to discord oauth
 */
hono_oidc.get('/auth', async (c) => {
    try {
        let { results } = await c.env.DB.prepare(
          "SELECT * FROM oidc_client WHERE client_id = ? LIMIT 1;",
        )
        .bind(c.req.query('client_id'))
        .all();

        if(results.length == 0){
            return c.json(new ErrMessage("auth error","client_id not found").dict(), 401)
        }
        
        let redirect_uri_arr = (results[0].redirect_uri as string).split(' ')

        if(c.req.query('response_type')!=="code"){
            //check response_type
            return c.json(new ErrMessage("auth error","response_type not supported.").dict(), 401)
        }else if(!redirect_uri_arr.includes((c.req.query('redirect_uri') as string))){
            //check redirect_uri
            return c.json(new ErrMessage("auth error","redirect URL is not allowed.").dict(), 401)
        }

        //save this request
        let code = hash_func(Math.random().toString())
        let oidc_state_hash = hash_func((c.req.query('state') as string)+code+Date.now().toString())
        await c.env.DB.prepare(
            "INSERT INTO oidc_req_tmp (oidc_state_hash, oidc_state, client_id, redirect_uri, code) VALUES (?, ?, ?, ?, ?);",
        )
        .bind(oidc_state_hash, c.req.query('state'), c.req.query('client_id'), c.req.query('redirect_uri'), code)
        .all();

        //scopes
        let scope_tmp = (results[0].scope as string).split(" ")
        scope_tmp.push("identify","email","guilds","guilds.members.read")
        let scopes = Array.from(new Set(scope_tmp))
        //remove custom scopes
        scopes = scopes.filter(function (item) {
            return item.indexOf("dcmg_") !== 0;
        });

        // redirect to discord login
        const params = new URLSearchParams({
            'client_id': c.env.DC_CLIENT_ID,
            'redirect_uri': c.env.DC_REDIRECT_URI,
            'response_type': 'code',
            'scope': scopes.join(" "),
            'state': oidc_state_hash,
            'prompt': 'none'
        }).toString()
        return c.redirect('https://discord.com/oauth2/authorize?' + params)
    
    } catch (e) {
        return c.json(new ErrMessage("auth error",(e as Error).message).dict(), 500);
    }
})

hono_oidc.post('/token', async (c) => {
    const body = await c.req.parseBody()
    const http_auth = c.req.header("Authorization")

    var client_id:string | undefined
    var client_secret:string | undefined

    if(http_auth){//client_secret_basic
        let credentials = basic_auth.parse(http_auth)
        client_id = credentials?.name
        client_secret = credentials?.pass
    }else{//client_secret_post
        client_id = (body['client_id'] as string)
        client_secret = (body['client_secret'] as string)
    }

    if(!client_id || !client_secret){
        return c.json(new ErrMessage("auth error","client_id or client_secret not found").dict(), 400)
    }

    const grant_type = body['grant_type']
    
    if(grant_type==="authorization_code"){ // authorization_code, get refresh_token, access_token, and id_token
        const code = (body['code'] as string)
        const redirect_uri = body['redirect_uri']
        let { results } = await c.env.DB.prepare(
            "SELECT T1.client_id, T1.scope, T2.code, T2.datr FROM (SELECT * FROM oidc_client WHERE client_id = ? AND client_secret = ?) AS T1 INNER JOIN (SELECT * FROM oidc_req_tmp WHERE client_id = ? AND code = ?) AS T2 ON T1.client_id=T2.client_id;",
        )
        .bind(client_id,client_secret,client_id,code)
        .all();
        if(results.length == 0){
            return c.json(new ErrMessage("token error","client_id or code not found").dict(), 401)
        }
    
        //get discord token
        let dc_access_token_resp = JSON.parse((results[0].datr as string))
        //Discord user info
        const userinfo:any = await discord_api.user_info(dc_access_token_resp["access_token"])
        //Discord user guilds (id list)
        const discord_userguilds_arr = await discord_api.user_guilds(dc_access_token_resp["access_token"])
        //generate roleClaims
        let white_list = discord_guild_role_whitelist(discord_userguilds_arr, Array.from(new Set((results[0].scope as string).split(" "))))
        let roleClaims:{[key: string]:string[]} = {}
        for(const [k,v] of Object.entries(white_list)){
            let g_role_ls = await discord_api.check_user_role(dc_access_token_resp["access_token"],k,v)
            if(g_role_ls !== null){
                roleClaims[k] = g_role_ls
            }
        }
        let preferred_username = userinfo["username"]
        if (userinfo["discriminator"] && userinfo["discriminator"] !== "0"){
            preferred_username += `#${userinfo['discriminator']}`
        }
        let displayName = userinfo["global_name"] ?? userinfo["username"]
        const idToken = await new jose.SignJWT({
            iss: `https://${c.env.ISS_DOMAIN}`,
            aud: client_id,
            preferred_username,
            ...userinfo,
            role_claims: roleClaims,
            sub: userinfo['email'],
            email: userinfo['email'],
            global_name: userinfo['global_name'],
            name: displayName,
            is_admin: c.env.DC_ADMIN_IDS.split(" ").includes(userinfo["id"]),
        })
        .setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('2h')
		.setAudience(client_id)
		.sign((await loadKeyPair(c.env.KV)).privateKey)
        
        await c.env.DB.prepare(
            "DELETE FROM oidc_req_tmp WHERE code=?;",
        )
        .bind(code)
        .all();
        return c.json({
            ...dc_access_token_resp,
            scope: (results[0].scope as string),
            id_token: idToken
        })
    }else if(grant_type==="refresh_token"){ // refresh_token, renew id_token and access_token
        let { results } = await c.env.DB.prepare(
            "SELECT client_id, scope FROM oidc_client WHERE client_id = ? AND client_secret = ? LIMIT 1;",
        )
        .bind(client_id,client_secret)
        .all();
        if(results.length == 0){
            return c.json(new ErrMessage("error","client_id and client_secret no match").dict(), 401)
        }
        const refresh_token = (body['refresh_token'] as string)

        //refresh discord access_token
        const discord_token_res:any = await discord_api.oauth2_token(c.env.DC_CLIENT_ID, c.env.DC_CLIENT_SECRET, "", refresh_token, "refresh_token")

        //verify user's current discord guilds and roles
        let passed = await discord_api.discord_user_permission_verify(discord_token_res["access_token"],results[0].scope as string)
        if(!passed){
            return c.json(new ErrMessage("error","refresh_token - deny").dict(), 401)
        }

        const userinfo:any = await discord_api.user_info(discord_token_res["access_token"])
        //Discord user guilds (id list)
        const discord_userguilds_arr = await discord_api.user_guilds(discord_token_res["access_token"])
        //generate roleClaims
        let white_list = discord_guild_role_whitelist(discord_userguilds_arr, Array.from(new Set((results[0].scope as string).split(" "))))
        let roleClaims:{[key: string]:string[]} = {}
        for(const [k,v] of Object.entries(white_list)){
            let g_role_ls = await discord_api.check_user_role(discord_token_res["access_token"],k,v)
            if(g_role_ls !== null){
                roleClaims[k] = g_role_ls
            }
        }
        let preferred_username = userinfo["username"]
        if (userinfo["discriminator"] && userinfo["discriminator"] !== "0"){
            preferred_username += `#${userinfo['discriminator']}`
        }
        let displayName = userinfo["global_name"] ?? userinfo["username"]
        const idToken = await new jose.SignJWT({
            iss: `https://${c.env.ISS_DOMAIN}`,
            aud: client_id,
            preferred_username,
            ...userinfo,
            role_claims: roleClaims,
            sub: userinfo['email'],
            email: userinfo['email'],
            global_name: userinfo['global_name'],
            name: displayName,
            is_admin: c.env.DC_ADMIN_IDS.split(" ").includes(userinfo["id"]),
        })
        .setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('2h')
		.setAudience(client_id)
		.sign((await loadKeyPair(c.env.KV)).privateKey)
        
        return c.json({
            ...discord_token_res,
            scope: (results[0].scope as string),
            id_token: idToken
        })
    }
})
/*==========================================*/
hono_well_known.get('/jwks.json', async (c) => {
    let publicKey = (await loadKeyPair(c.env.KV)).publicKey
	return c.json({
		keys: [{
			alg: 'RS256',
			kid: 'jwtRS256',
			...(await crypto.subtle.exportKey('jwk', publicKey))
		}]
	})
})

hono_well_known.get('/openid-configuration', async (c) => {
	return c.json({
		issuer: `https://${c.env.ISS_DOMAIN}`,
        authorization_endpoint: `https://${c.env.ISS_DOMAIN}/oauth2/auth`,
        token_endpoint: `https://${c.env.ISS_DOMAIN}/oauth2/token`,
        userinfo_endpoint: `https://discordapp.com/api/v10/users/@me`,
        jwks_uri: `https://${c.env.ISS_DOMAIN}/.well-known/jwks.json`,
        subject_types_supported: ["public"],
        response_types_supported:["code"],
        id_token_signing_alg_values_supported: ["RS256"],
        grant_types_supported:["authorization_code"],
        claims_supported:[
            "iss",
            "aud",
            "sub",
            "email",
            "global_name",
            "name",
            "role_claims",
            "id",
            "username",
            "discriminator",
            "avatar",
            "preferred_username",
            "is_admin"
        ]
	})
})

export default hono_oidc