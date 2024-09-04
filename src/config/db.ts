import {Pool} from 'pg'
import dotenv from 'dotenv';
dotenv.config();
export const pool = new Pool({
    user: process.env.DB_USER,
    host:process.env.DB_HOST,
    database:process.env.DB_DATABASE,
    password:process.env.DB_PASSWORD as string,
    port: parseInt(process.env.DB_PORT || '5432'),
    max:10,
    idleTimeoutMillis:30000,
    connectionTimeoutMillis:2000
})

