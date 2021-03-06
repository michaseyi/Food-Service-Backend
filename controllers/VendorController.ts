import { Request, Response, NextFunction } from "express";
import { VendorLoginInput } from "../dto";
import { GenerateSignature, ValidatePassword } from "../utility";
import { FindVendor } from "./AdminController";

export const VendorLogin = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = <VendorLoginInput>req.body;

  const existingVendor = await FindVendor("", email);

  if (existingVendor !== null) {
    const validation = await ValidatePassword(password, existingVendor.password, existingVendor.salt);

    if (validation) {
      const signature = GenerateSignature({
        _id: existingVendor.id,
        email: existingVendor.email,
        name: existingVendor.name,
        foodType: existingVendor.foodType,
      });

      return res.json(signature);
    } else {
      return res.json({ message: "Password is not valid" });
    }
  }

  return res.json({ message: "Login credentials not valid" });
};

export const GetVendorProfile = async (req: Request, res: Response, next: NextFunction) => {};

export const UpdateVendorProfile = async (req: Request, res: Response, next: NextFunction) => {};

export const UpdateVendorService = async (req: Request, res: Response, next: NextFunction) => {};
 