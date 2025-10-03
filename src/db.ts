import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const MONGO_DB_URL: string = process.env.MONGO_DB_URL || "";

const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(MONGO_DB_URL);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error: unknown) {
    if (error instanceof Error) {
      console.error(`Error: ${error.message}`);
    } else {
      console.error("Unknown error occurred while connecting to MongoDB");
    }
    process.exit(1);
  }
};

export default connectDB;
