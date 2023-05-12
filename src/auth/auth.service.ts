import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import e, { Request, Response } from 'express';
import { SignInAuthDto } from './dto/signIn.dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: AuthDto) {
    const { email, password, firstName, lastName, phoneNumber } = dto;

    const userExists = await this.prisma.user.findUnique({
      where: { email },
    });

    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

    const userPhoneExists = await this.prisma.user.findUnique({
      where: { phoneNumber },
    });

    if (userPhoneExists) {
      throw new BadRequestException('Phone Number already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        firstName,
        lastName,
        email,
        phoneNumber,
        hashedPassword,
      },
    });

    return { message: 'User created succefully' };
  }

  async signin(dto: SignInAuthDto, req: Request, res: Response) {
    const { emailOrPhoneNumber, password } = dto;
    console.log(emailOrPhoneNumber, password);

    const foundUser = await this.findUser(emailOrPhoneNumber);

    if (!foundUser) {
      throw new BadRequestException('User not found');
    }

    const compareSuccess = await this.comparePasswords({
      password,
      hash: foundUser.hashedPassword,
    });

    if (!compareSuccess) {
      throw new BadRequestException('Incorrect Password');
    }

    const token = await this.signToken({
      userId: foundUser.id,
      email: foundUser.email,
    });

    if (!token) {
      throw new ForbiddenException('Could not signin');
    }

    res.cookie('token', token, {});

    return res.send({ message: 'Logged in succefully' });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('token');

    return res.send({ message: 'Logged out succefully' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;

    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePasswords(args: { hash: string; password: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }

  async signToken(args: { userId: string; email: string }) {
    const payload = {
      id: args.userId,
      email: args.email,
    };
    const token = await this.jwt.signAsync(payload, {
      secret: jwtSecret,
    });

    return token;
  }

  async findUser(emailOrPhoneNumber: string) {
    const emailRegex: RegExp =
      /^([a-z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,63})$/;
    const phoneNumberRegex: RegExp =
      /^(\+[0-9]{1,3}\s?)?(\(?[0-9]{4,5}\)?[-.\s]?)?[0-9]{3,5}[-.\s]?[0-9]{0,3}$/;

    if (emailRegex.test(emailOrPhoneNumber)) {
      let email = emailOrPhoneNumber;
      const foundUser = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });
      return foundUser;
    } else if (phoneNumberRegex.test(emailOrPhoneNumber)) {
      let phoneNumber = emailOrPhoneNumber;
      const foundUser = await this.prisma.user.findUnique({
        where: {
          phoneNumber,
        },
      });

      return foundUser;
    }
  }
}
