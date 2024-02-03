import asyncHandler from "../middlewares/asyncHandler.js";
import User from "../models/userModels.js";
import pkg from 'bcryptjs';
import createToken from '../utils/createToken.js'
const bcrypt = pkg;

const createUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check for missing inputs
        if (!username || !email || !password) {
            throw new Error("Please fill in all the inputs");
        }

        // Check if a user with the provided email already exists
        const userExists = await User.findOne({ email });

        if (userExists) {
            return res.status(400).json({ message: "User already exists" });
        }
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)


        // Create a new user instance
        const newUser = new User({ username, email, password:hashedPassword });

        // Save the new user to the database
        await newUser.save();
        createToken(res, newUser._id);


        // Respond with user details
        res.status(201).json({
            _id: newUser._id,
            username: newUser.username,
            email: newUser.email,
            isAdmin: newUser.isAdmin,
        });
    } catch (error) {
        // Handle any errors during the try block
        res.status(400).json({ message: error.message });
    }
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
  
    if (existingUser) {
      try {
        const isPasswordValid = await bcrypt.compare(password, existingUser.password);
  
        if (isPasswordValid) {
          createToken(res, existingUser._id);
          res.status(201).json({
            _id: existingUser._id,
            username: existingUser.username,
            email: existingUser.email,
            isAdmin: existingUser.isAdmin,
          });
          return;
        } else {
          res.status(401).json({ message: 'Invalid password' });
          return;
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
        return;
      }
    } else {
      res.status(404).json({ message: 'User not found' });
      return;
    }
  });
  
  const logoutCurrentUser = asyncHandler(async(req,res)=>{
    res.cookie('jwt','',{
   httyOnly: true,
   expires: new Date(0),
 })
 res.status(200).json({message:"logged out successfully"}) })

 const getAllUsers = asyncHandler(async(req,res)=> {
    const users = await User.find({})
    res.json(users)
 });

 const getCurrentUserProfile = asyncHandler(async(req,res)=>{
  const user = await User.findById(req.user._id)
  if (user) {
    res.json ({
      _id: user._id,
      username: user.username,
      email: user.email,
    })
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
 })
 
 const updateCurrentUserProfile = asyncHandler(async(req,res)=>{
  const user = await User.findById(req.user._id)
  if (user) {
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;

    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);
      user.password = hashedPassword;
    }

    const updatedUser = await user.save();

    res.json({
      _id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      isAdmin: updatedUser.isAdmin,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
 })

 const deleteUserById = asyncHandler(async(req,res)=> {
  const user = await User.findById(req.params.id);

  if (user) {
    if (user.isAdmin) {
      res.status(400);
      throw new Error("Cannot delete admin user");
    }

    await User.deleteOne({ _id: user._id });
    res.json({ message: "User removed" });
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
 })
 const getUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).select("-password");

  if (user) {
    res.json(user);
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});
const updateUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (user) {
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    user.isAdmin = Boolean(req.body.isAdmin);

    const updatedUser = await user.save();

    res.json({
      _id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      isAdmin: updatedUser.isAdmin,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});
export { createUser,loginUser,logoutCurrentUser,
  getAllUsers,getCurrentUserProfile,
  updateCurrentUserProfile, deleteUserById,
  getUserById,
  updateUserById,};
