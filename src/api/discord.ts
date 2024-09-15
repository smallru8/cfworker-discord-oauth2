import { loadKeyPair, ErrMessage, Bindings, hash_func, discord_guild_role_whitelist } from '../utils'

export async function oauth2_token(client_id: string, client_secret:string, redirect_uri:string, code:string, grant_type:string="authorization_code"){
    var params_dict
    var params_gen_dict = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': grant_type,
    }
    
    if(grant_type==="authorization_code"){
        params_dict = {
            ...params_gen_dict,
            'redirect_uri': redirect_uri,
            'code': code
        }
    }else if(grant_type==="refresh_token"){
        params_dict = {
            ...params_gen_dict,
            'refresh_token': code
        }
    }

    const params = new URLSearchParams(params_dict).toString()

    const discord_token_res = await fetch('https://discord.com/api/v10/oauth2/token', {
		method: 'POST',
		body: params,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	}).then(res => res.json())
    return discord_token_res
}

export async function user_info(access_token:string){
    const userInfo = await fetch('https://discord.com/api/v10/users/@me', {
		headers: {
			'Authorization': 'Bearer ' + access_token
		}
	}).then(res => res.json())
    return userInfo
}

export async function user_guilds(access_token:string){
    const userGuilds = await fetch('https://discord.com/api/v10/users/@me/guilds', {
		headers: {
			'Authorization': 'Bearer ' + access_token
		}
	})
    let guilds:string[] = []
    if (userGuilds.status === 200) {
		const guildsJson:any[] = await userGuilds.json()
		guilds = guildsJson.map(item => {
			return item['id']
		})
	}
    return guilds
}

/**
 * check role
 * return null if deny else return string[...roles]
 * @param access_token
 */
export async function check_user_role(access_token:string, guild_id:string, role_id_allowed_ls:string[]){
    const member:any = await fetch(`https://discord.com/api/v10/users/@me/guilds/${guild_id}/member`, {
		headers: {
			'Authorization': 'Bearer ' + access_token
		}
	})

    let roles:string[] = []
    if (member.status === 200) {
        //white list not set, passed
        if(role_id_allowed_ls.length == 0)
            return roles

        let role_obj_ls:string[] = (await member.json())["roles"]
        //console.log(role_obj_ls)//debug
        /*
        let role_id_ls:string[] = []
        role_id_ls = role_obj_ls.map(item => {
            return item['id']
        })
        */
        for(var i=0;i<role_id_allowed_ls.length;i++)
            if(role_obj_ls.includes(role_id_allowed_ls[i])){
                roles.push(role_id_allowed_ls[i])
            }
        if(roles.length == 0){
            return null
        }
        return roles
    }
    return null
}

/**
 * check if user has specific guilds and roles
 * scope format: ```dcmg_<guild_id>_<role_id>```
 * @param access_token 
 * @param scopes 
 * @returns 
 */
export async function discord_user_permission_verify(access_token:string, scopes:string){
    //Discord user guilds (id list)
    const discord_userguilds_arr = await user_guilds(access_token)
    let white_list = discord_guild_role_whitelist(discord_userguilds_arr, Array.from(new Set(scopes.split(" "))))
    let passed = false
    if("0" in white_list){//whitelist not set passed
        passed = true
    }else{
        for(var i=0;i<discord_userguilds_arr.length;i++){
            if(discord_userguilds_arr[i] in white_list){
                let tmp_gid = discord_userguilds_arr[i]
                let check_res = check_user_role(access_token,tmp_gid,white_list[tmp_gid])
                if(check_res!==null){
                    passed = true
                    break
                }
            }
        }
    }
    return passed
}