import { NextFunction, Request, Response } from "express";
import { AuthPayload } from "../dto/Auth.dto";
import { ValidateSignature } from "../utility";

declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}

export interface UserRequest extends Request {
  user?: AuthPayload;
}

export const Authentication = async (req: Request, res: Response, next: NextFunction) => {
  const validate = await ValidateSignature(req);

  if (validate) {
    next();
  } else {
    return res.json({ ssmessage: "User not Authorized" });
  }
};