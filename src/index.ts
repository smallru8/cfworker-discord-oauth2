import { Hono } from 'hono'
import hono_oidc from "./oidc"
import hono_discord from './discord'
import hono_well_known from './well_known'
import { clear_db_oidc_req_tmp } from './jobs/clear_timeout_data'
interface Env {}

const app = new Hono()

app.get('/', (c) => {
  return c.text('404 page not found',404)
})

app.route("/oauth2",hono_oidc)
app.route("/discord",hono_discord)
app.route("/.well-known",hono_well_known)

export default {
    /** cloudflare trigger job*/
    scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
        const delayedProcessing = async () => {
            //clear timeout data
            await clear_db_oidc_req_tmp(env);
        };
        ctx.waitUntil(delayedProcessing());
    },
    /** hono */
    fetch(request: Request, env: Env, ctx: ExecutionContext) {
        return app.fetch(request, env, ctx);
    },
};