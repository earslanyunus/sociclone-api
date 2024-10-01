import { Options, argon2id } from 'argon2';
import dotenv from 'dotenv';

dotenv.config();

export const argon2Config: Options = {
    type: argon2id,
    memoryCost: parseInt(process.env.ARGON2_MEMORY_COST as string),
    timeCost: parseInt(process.env.ARGON2_TIME_COST as string),
    parallelism: parseInt(process.env.ARGON2_PARALLELISM as string),
    hashLength: parseInt(process.env.ARGON2_HASH_LENGTH as string),
};
