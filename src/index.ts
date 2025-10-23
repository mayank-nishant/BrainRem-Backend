import express from "express";
import type { Response, Request } from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { z } from "zod";
import cors from "cors";
import connectDB from "./db.js";
import { UserModel, LinkModel, ContentModel } from "./models.js";
import { userMiddleware } from "./middleware.js";

dotenv.config();

const PORT = process.env.PORT ? parseInt(process.env.PORT) : 4000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";

const app = express();

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

await connectDB();

const userSchema = z.object({
  username: z.string().min(3),
  password: z.string().min(6),
});

const contentSchema = z.object({
  link: z.url().optional(),
  type: z.string().min(1),
  title: z.string(),
  note: z.string().optional(),
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port: ${PORT}`);
});

app.post("/api/v1/signup", async (req: Request, res: Response) => {
  try {
    const { username, password } = userSchema.parse(req.body);
    const existingUser = await UserModel.findOne({ username });
    if (existingUser) return res.status(409).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await UserModel.create({ username, password: hashedPassword });
    res.json({ message: "User signed up successfully" });
  } catch (e: any) {
    res.status(400).json({ message: `Error : ${e.message}` });
  }
});

app.post("/api/v1/signin", async (req: Request, res: Response) => {
  try {
    const { username, password } = userSchema.parse(req.body);
    const user = await UserModel.findOne({ username });
    if (!user) return res.status(403).json({ message: "Invalid credentials" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(403).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ message: "User signed in successfully", token });
  } catch (e: any) {
    res.status(400).json({ message: `Error : ${e.message}` });
  }
});

app.post("/api/v1/content", userMiddleware, async (req: Request, res: Response) => {
  try {
    const { link, type, title, note } = contentSchema.parse(req.body);
    await ContentModel.create({
      link,
      type,
      note,
      title: title || "Untitled",
      userId: req.userId,
      tags: [],
    });

    res.json({ message: "Content added" });
  } catch (e: any) {
    res.status(400).json({ message: `Error : ${e.message}` });
  }
});

app.get("/api/v1/content", userMiddleware, async (req: Request, res: Response) => {
  const content = await ContentModel.find({ userId: req.userId }).populate("userId", "username");
  res.json({ content });
});

app.delete("/api/v1/content", userMiddleware, async (req: Request, res: Response) => {
  try {
    const { contentId } = req.body;
    if (!contentId) return res.status(400).json({ message: "Content ID required" });
    await ContentModel.deleteOne({ _id: contentId, userId: req.userId });
    res.json({ message: "Deleted" });
  } catch (e: any) {
    res.status(400).json({ message: `Error : ${e.message}` });
  }
});

app.put("/api/v1/content", userMiddleware, async (req: Request, res: Response) => {
  try {
    const { contentId, link, type, title, note } = req.body;

    if (!contentId) {
      return res.status(400).json({ message: "Content ID is required for update" });
    }

    contentSchema.parse({ link, type, title, note });

    const updated = await ContentModel.findOneAndUpdate(
      { _id: contentId, userId: req.userId },
      {
        $set: {
          link,
          type,
          title: title || "Untitled",
          note,
        },
      },
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ message: "Content not found or unauthorized" });
    }

    res.json({ message: "Content updated successfully", updated });
  } catch (e: any) {
    res.status(400).json({ message: `Error: ${e.message}` });
  }
});

app.post("/api/v1/brain/share", userMiddleware, async (req: Request, res: Response) => {
  try {
    const { share } = req.body;
    if (share) {
      const existingLink = await LinkModel.findOne({ userId: req.userId });
      if (existingLink) return res.json({ hash: existingLink.hash });
      const hash = Math.random().toString(36).substring(2, 12);
      await LinkModel.create({ userId: req.userId, hash });
      res.json({ hash });
    } else {
      await LinkModel.deleteOne({ userId: req.userId });
      res.json({ message: "Removed link" });
    }
  } catch (e: any) {
    res.status(400).json({ message: `Error : ${e.message}` });
  }
});

app.get("/api/v1/brain/:shareLink", async (req: Request, res: Response) => {
  try {
    const { shareLink } = req.params;
    const link = await LinkModel.findOne({ hash: shareLink });
    if (!link) return res.status(404).json({ message: "Invalid share link" });

    const user = await UserModel.findById(link.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const content = await ContentModel.find({ userId: link.userId });
    res.json({ username: user.username, content });
  } catch (e: any) {
    res.status(400).json({ message: `Error : ${e.message}` });
  }
});
