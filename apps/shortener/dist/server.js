"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const link_routes_1 = __importDefault(require("./routes/link.routes"));
const logger_1 = __importDefault(require("./logger"));
const redis_1 = require("./services/redis");
dotenv_1.default.config();
const apps = (0, express_1.default)();
const PORT = process.env.PORT || 5001;
(async () => {
    await (0, redis_1.connectRedis)(); //  connect Redis after env is loaded
})();
apps.use((0, cors_1.default)({ origin: '*' }));
apps.use(express_1.default.json());
//health check
apps.get('/health', (req, res) => {
    logger_1.default.info('Shortner health check');
    res.json({ status: 'ok', message: 'URL Shortener running!' });
});
apps.use('/api', link_routes_1.default); //under api/
apps.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
});
apps.listen(PORT, () => {
    logger_1.default?.info(`Shortener running on http://localhost:${PORT}`);
});
//# sourceMappingURL=server.js.map