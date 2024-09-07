import express from "express";
import authRoutes from './auth/routes/index';
import { pool } from "./config/db";
import passport from './config/passport';

const app = express();

const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(passport.initialize());

app.use('/auth', authRoutes);



app.listen(PORT, () => {
  console.log('Server is running ');
});

process.on('SIGINT', () => {
  pool.end(() => {
    console.log('Database connection closed');
    process.exit(0);
  });
});