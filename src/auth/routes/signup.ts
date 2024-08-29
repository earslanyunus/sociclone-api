import express from 'express';

const router = express.Router()

router.post('/',(req,res)=>{
    res.send('signup route is working')
})

export default router