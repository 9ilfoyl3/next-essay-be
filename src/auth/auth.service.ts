import { Injectable } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  login(loginDto: LoginDto) {
    return loginDto;
  }
  register(registerDto: RegisterDto) {
    return registerDto;
  }
}
