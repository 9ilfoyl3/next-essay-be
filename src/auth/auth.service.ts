import { HttpException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { hash, verify } from 'argon2';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}
  async login(loginDto: LoginDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        phone: loginDto.phone,
      },
    });
    if (user) {
      const isPasswordCorrect = await verify(user.password, loginDto.password);
      if (isPasswordCorrect) {
        return user;
      } else {
        throw new HttpException('Invalid password', 400);
      }
    } else {
      throw new HttpException('User not found', 400);
    }
  }
  async register(registerDto: RegisterDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        phone: registerDto.phone,
      },
    });

    if (user) {
      throw new HttpException('User already exists', 400);
    }

    const newUser = await this.prisma.user.create({
      data: {
        phone: registerDto.phone,
        password: await hash(registerDto.password),
      },
    });

    return newUser;
  }
}
