import express from 'express';
import dotenv from 'dotenv'
import { connectDB } from './db/connectDB.js';
import authRoutes from './routes/auth.route.js'
import cookieParser from 'cookie-parser'

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json()) // allows us to parse incoming requests with JSON payloads
app.use(cookieParser()); // allow us to parse incoming cookies
app.use("/api/auth", authRoutes)

app.listen(PORT, () => {
    connectDB();
    console.log("Server is running on port:", PORT);
});

// sajeevantechwork
// tGnnLcIIYKyePRzz
