import express from "express";
import authRoutes from './auth/routes/index';
import passport from './config/passport';
import cors from "cors";
import dotenv from 'dotenv';
dotenv.config();
const app = express();


const PORT = process.env.PORT || 3000;
app.use(cors({
  origin: process.env.API_URL,
  credentials: true,
}));  
app.get('/', (req, res) => {
  res.send('Hello World');
});
app.use(express.json());
app.use(passport.initialize());

app.use('/auth', authRoutes);



app.listen(PORT, () => {
  console.log('Server is running ');
});

