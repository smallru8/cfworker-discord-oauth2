import { Hono } from 'hono'
import { Bindings } from './utils'

const hono_well_known = new Hono<{ Bindings: Bindings }>()

export default hono_well_known