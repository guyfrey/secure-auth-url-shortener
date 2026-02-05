"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const link_controller_1 = require("../controllers/link.controller");
const router = (0, express_1.Router)();
router.post('/shorten', link_controller_1.shorten);
router.get('/:shortCode/stats', link_controller_1.getStats);
router.get('/:shortCode', link_controller_1.redirect);
exports.default = router;
//# sourceMappingURL=link.routes.js.map