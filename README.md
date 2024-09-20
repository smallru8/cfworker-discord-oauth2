# cfworker-discord-oauth2

Discord oauth2 service with guild role whitelist.  
Powered by Cloudflare worker.  

(not completely finished)  

## Installation  
1. Create cloudflare D1 database and cloudflare KV  
2. Create discord oauth2 app, and add ```https://your.domain/discord/callback``` to redirects  
3. Fork this repo  
4. Set Github variables and secrets  
    i. Add repository secrets  
    ```
    DC_CLIENT_SECRET=<discord_app_client_secret>
    CLOUDFLARE_API_TOKEN=<cloudflare_api_token>
    ```
    ii. Add repository variables  
    ```
    CF_D1_ID=<cloudflare_d1_id>
    CF_D1_NAME=<cloudflare_d1_name>
    CF_KV_ID=<cloudflare_kv_id>
    DC_ADMIN_IDS=<your_discord_id>
    DC_CLIENT_ID=<discord_app_client_id>
    ISS_DOMAIN=<your.domain>
    ```
5. Run workflow  
    Github Action -> Wrangler Deploy -> run workflow  
    
## Usage  
### Endpoints  
openid-configuration: ```https://your.domain/.well-known/openid-configuration```  

### Create oauth client
Go to your Cloudflare D1 database -> ```oidc_client``` table  

Add data:
```
client_id: example: 6c19c2cd022f400000000e9aae1eb2b9
client_secret: example: bnkcasCJAqwcoA12Assewn
owner_id: <your_discord_id>
scope: dcmg_298720010287595568_1246982337719941156 dcmg_<guild_id>_<role_id>
redirect_uri: https://example1.com/callback https://example2.com/callback
```
```client_id```: oauth2 client id  
```client_secret```: oauth2 client secret  
```owner_id```: your discord id  
```scope```: Support [Discord scopes](https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes) and dcmg_<discordGuildId>_<discordRoleId>. You can use multiple dcmg\_ scope. The user must have one of the corresponding Guild_id and Role_id to pass the verification.  
```redirect_uri```: oauth2 redirect urls  

Done! You can use it in applications that support OAuth2 login.  
Example:
![pic](https://raw.githubusercontent.com/smallru8/cfworker-discord-oauth2/refs/heads/main/docs/upload_b5b5adda4995f1665ae70a3037bd865e.png)
