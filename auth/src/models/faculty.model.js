import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose, { Schema } from "mongoose";
const facultySchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    facultyId: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    roles: {
      type: [String],
    },
  },
  { timestamps: true },
);

facultySchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

facultySchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

facultySchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      type: "faculty",
      email: this.email,
      facultyId: this.facultyId,
      name: this.name,
      roles: this.roles,
    },
    "c433b3a0a14642dde7d5b5c77b19814eddd3978d246ba01e279236bca59b8107990212ec90c8dfc38421e862a5d7aabe952795843eb61194b7de64cc730b98e4",
    {
      expiresIn: "1d",
    },
  );
};

facultySchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    "4326b08c6e28c09d451cdacb7b1ef9302156a632aa665cc24c4769bc3019a4098c8cd0b957017175a956fb4191ed3b6ef244ba86e0ca900dca68d32a701bbd5e",
    {
      expiresIn: "10d",
    },
  );
};

const Faculty = mongoose.model("Faculty", facultySchema);

export default Faculty;
