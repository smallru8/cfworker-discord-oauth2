
export async function clear_db_oidc_req_tmp(env:any){
    await (env.DB as D1Database).prepare(
        "DELETE FROM oidc_req_tmp WHERE created_at < (datetime('now', '-10 minutes'));",
    )
    .all();
}
