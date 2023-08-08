const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const dotenv=require('dotenv');
dotenv.config();
const JWT_SECRET=process.env.JWTSECRET;

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error("Not valid email");
      }
    },
  },
  password: {
    type: String,
    required: true,
  },
  cpassword: {
    type: String,
    required: true,
  },
  tokens: [
    {
      token: {
        type: String,
        required:true
      },
    },
  ],
  verifytoken:{
    type:String,

  }
});




//hash password
userSchema.pre('save',async function(next){
    if(this.isModified("password")){
        this.password= await bcrypt.hash(this.password,12);
        this.cpassword= await bcrypt.hash(this.cpassword,12);
    }
    next();
})


//generate token
userSchema.methods.generateAuthtoken=async function (){
    try {
        let token1=jwt.sign({_id:this._id},JWT_SECRET,{expiresIn:"1d"});
        this.tokens=this.tokens.concat({token:token1})
        await this.save();
        return token1;
    } catch (error) {
        res.status(422).json(error);
    }
}

//creating model
const userdb=new mongoose.model('users',userSchema);
module.exports=userdb;