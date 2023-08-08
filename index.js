const express=require('express');
const app=express();
const port=8081;
require('./db/conn');
const router=require('./routes/router');
const cors=require('cors');
const cookieParser=require('cookie-parser');
const dotenv=require('dotenv');
dotenv.config();

app.use(cors({
    origin:true
}))

app.use(express.json());
app.use(router);
app.use(cookieParser());
 
app.listen(process.env.PORT,()=>{console.log(`server listening on ${process.env.PORT}`)})