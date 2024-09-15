import {Md5} from 'ts-md5'

export class ErrMessage {

    error: string
    message: string

    constructor(error: string, message: string){
        this.error = error
        this.message = message
    }
    dict(){
        return { error:this.error,error_description:this.message }
    }
    params(){
        return new URLSearchParams({
            'error': this.error,
            'error_description': this.message
        }).toString()
    }
}

/**
 * process.env.NAME on Node.js or Bun
 * the value written in `wrangler.toml` on Cloudflare
 */
export type Bindings = {
    DB: D1Database
    KV: any
    ISS_DOMAIN: string
    DC_CLIENT_ID: string
    DC_REDIRECT_URI: string
    DC_CLIENT_SECRET: string
    DC_ADMIN_IDS: string
}

const algorithm = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 2048,
	publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	hash: { name: 'SHA-256' },
}

const importAlgo = {
	name: 'RSASSA-PKCS1-v1_5',
	hash: { name: 'SHA-256' },
}

export function hash_func(data:string){
    /*
    const myText = new TextEncoder().encode(data);

    const myDigest = await crypto.subtle.digest(
    {
        name: 'SHA-256',
    },
        myText
    );
    const hexString = [...new Uint8Array(myDigest)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    return hexString
    */
    return Md5.hashStr(data)
}

export async function loadKeyPair(cf_kv: any) {
    let keyPair: { [key: string]: any } = {};
	let keyPairJson = await cf_kv.get('keys', { type: 'json' })

	if (keyPairJson !== null) {
		keyPair.publicKey = await crypto.subtle.importKey('jwk', keyPairJson.publicKey, importAlgo, true, ['verify'])
		keyPair.privateKey = await crypto.subtle.importKey('jwk', keyPairJson.privateKey, importAlgo, true, ['sign'])
		return keyPair
	} else {
		keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

		await cf_kv.put('keys', JSON.stringify({
			privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
			publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey)
		}))
		return keyPair
	}
}

/**
 * generate whitelist
 * { \<guild_id\>:[\<role_id_1\>,\<role_id_2\>,...],... }
 * @param user_guilds user's guild id list
 * @param scopes 
 * @returns 
 */
export function discord_guild_role_whitelist(user_guilds:string[], scopes:string[]){
    let white_list:{[key: string]:string[]} = {}

    //remove non custom scopes
    scopes = scopes.filter(function (item) {
        return item.indexOf("dcmg_") == 0;
    });
    
    if(scopes.length == 0){//whitelist not set return {"0":[]}
        white_list["0"] = []
        return white_list;
    }

    scopes.forEach((ele) => {
        let g_r = ele.replaceAll("dcmg_","").split("_")
        if(user_guilds.includes(g_r[0])){
            if(g_r[0] in white_list){
                white_list[g_r[0]].push(g_r[1])
            }else{
                if(g_r.length==2)
                    white_list[g_r[0]] = [g_r[1]]
                else
                    white_list[g_r[0]] = []
            }
        }
    })

    return white_list
}