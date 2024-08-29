import express, { Request, Response } from "express";
import authRoutes from './auth/routes/index'
const app = express()

const PORT = process.env.PORT || 3000;

app.use('/auth',authRoutes)


app.listen(PORT,()=>{
    console.log('Server is running');
    
})