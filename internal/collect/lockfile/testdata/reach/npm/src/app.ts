import express from "express";
import type { Request } from "express";
const fp = require("lodash/fp");
import { pool } from "./db";
export const app = express();
