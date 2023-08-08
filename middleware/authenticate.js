const jwt=require('jsonwebtoken');
const userdb=require('../models/userSchema');
const dotenv=require('dotenv');
dotenv.config();

const JWT_SECRET=process.env.JWTSECRET

const authenticate=async (req,res,next)=>{
    try {
        const token=req.headers.authorization;
        
        const verifytoken=jwt.verify(token,JWT_SECRET);
        // console.log(verifytoken)
        const rootUser=await userdb.findOne({_id:verifytoken._id});
        // console.log(rootUser)
        if(!rootUser){
            throw new Error("user not found")
        }
        req.token=token;
        req.rootUser=rootUser;
        req.userId=rootUser._id;
        next()

    } catch (error) {
        res.status(400).json({status:400,message:"Unauthorized no token provided"})
    }
}
module.exports=authenticate;