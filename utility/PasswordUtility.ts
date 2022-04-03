import bcrypt from "bcrypt";
import { Request } from "express";
import jwt from "jsonwebtoken";
import { APP_SECRET } from "../config";
import { VendorPayload } from "../dto";
import { AuthPayload } from "../dto/Auth.dto";
import { UserRequest } from "../middlewares";

export const GenerateSalt = async () => {
  return await bcrypt.genSalt();
};

export const GeneratePassword = async (password: string, salt: string) => {
  return await bcrypt.hash(password, salt);
};

export const ValidatePassword = async (enteredPassword: string, savedPassword: string, salt: string) => {
  return (await GeneratePassword(enteredPassword, salt)) === savedPassword;
};

export const GenerateSignature = (payload: VendorPayload) => {
  return jwt.sign(payload, APP_SECRET, { expiresIn: "30m" });
};

export const ValidateSignature = async (req: UserRequest) => {
  const signature = req.get("Authorization");

  if (signature) {
    const payload = await (<AuthPayload>jwt.verify(signature.split(" ")[1], APP_SECRET));

    req.user = payload;

    return true;
  }

  return false;
};
