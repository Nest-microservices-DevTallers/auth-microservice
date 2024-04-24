import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as Bcript from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  onModuleInit() {
    this.$connect();
    this.logger.log(`🚀 Connect with DB`);
  }

  async register(registerUserDto: RegisterUserDto) {
    const user = await this.user.findUnique({
      where: {
        email: registerUserDto.email,
      },
    });

    if (user)
      throw new RpcException({
        status: 400,
        message: 'User already exists',
      });

    const newUser = await this.user.create({
      data: {
        ...registerUserDto,
        password: await Bcript.hash(registerUserDto.password, 10),
      },
    });

    return {
      user: newUser,
      token: '1q2w3e4r',
    };
  }

  login(loginUserDto: LoginUserDto) {
    return loginUserDto;
  }

  verifyToken() {
    return 'This action verify token';
  }
}
