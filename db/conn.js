const mongoose=require('mongoose');
const dotenv=require('dotenv');
dotenv.config();

const db=process.env.MONGO_URL;
mongoose.connect(db,{useUnifiedTopology:true,useNewUrlParser:true}).then(()=>console.log("db connected")).catch(err=>{console.log(err)})