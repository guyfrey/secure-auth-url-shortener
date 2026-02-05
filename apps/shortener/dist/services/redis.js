"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.redis = void 0;
exports.connectRedis = connectRedis;
const redis_1 = require("redis");
const logger_1 = __importDefault(require("../logger"));
const client = (0, redis_1.createClient)({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});
client.on('error', (err) => logger_1.default.error('Redis Client Error', err));
exports.redis = client;
async function connectRedis() {
    if (!client.isOpen) {
        await client.connect();
    }
}
//# sourceMappingURL=redis.js.map