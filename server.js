require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
var bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Schema = mongoose.Schema;
const app = express();
const port = 6000;

const uri = process.env.MONGODB_URL;
mongoose.connect(uri);
mongoose.connection.on("connected", () => {
    console.log("database connected");
});

mongoose.connection.on("error", () => {
    console.log("database not connected");
});

app.use(bodyParser.json());

//create schema for db
const userSchema = new Schema({
    fname: String,
    lname: String,
    email: String,
    password: String,
});
const User = mongoose.model("User", userSchema);

const userTask = new Schema({
    name: String,
    type: String,
    user: {
        type: Schema.Types.ObjectId,
        ref: "User",
    },
});

const Task = mongoose.model("Task", userTask);

app.post("/users", async (req, res) => {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password, salt);
    const password = hash;
    const userObj = {
        fname: req.body.fname,
        lname: req.body.lname,
        email: req.body.email,
        password: password,
    };
    const user = new User(userObj);
    await user.save();
    res.status(201).json(user);
});

app.post("/users/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email });
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
        res.status(401).json({ message: "wrong password" });
    } else {
        const accessToken = await jwt.sign(
            { email: user.email, id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: "1000d" }
        );
        const refreshToken = await jwt.sign(
            { email: user.email, id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: "1000d" }
        );
        userObj = user.toJSON(user);
        userObj["accessToken"] = accessToken;
        userObj["refreshToken"] = refreshToken;
        res.status(201).json(userObj);
    }
});

const authenticateToken =(req,res,next) =>{
    const authHeader = req.headers.authorization;
    const token = authHeader.split(" ")[1]
    if(!token) {
        res.status(401).json({message:"Unauthorize user (token e somossa ase)"})
    } else {
        const decoded = jwt.verify(token, process.env.JWT_SECRET,(error,user)=>{
            if(error) {
                res.status(401).json({message:"unauthorize user(token verify hoini)"})
            } else {
                req.user = user
                next()
            }
        });
    }
}

app.post("/createTask",authenticateToken,async (req, res) => {
    const taskObj = {
        name: req.body.name,
        type: req.body.type,
        user: req.user.id,
    };
    const task = new Task(taskObj);
    await task.save()
    res.status(201).json(task)
});

app.listen(port, () => {
    console.log("Connected to port 6000");
});
