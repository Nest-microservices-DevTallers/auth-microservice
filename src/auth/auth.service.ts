import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import * as Bcrypt from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';
import { PayloadInterface } from './interfaces';
import { envs } from '@server/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log(`🚀 Connect with DB`);
  }

  async signJWT(payload: PayloadInterface) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = await this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
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
        password: await Bcrypt.hash(registerUserDto.password, 10),
      },
    });

    const { password: _, ...res } = newUser;

    return {
      user: res,
      token: await this.signJWT(res),
    };
  }

  async login(loginUserDto: LoginUserDto) {
    const user = await this.user.findUnique({
      where: {
        email: loginUserDto.email,
      },
    });

    if (!user)
      throw new RpcException({
        status: 400,
        message: 'Invalid credentials',
      });

    const isPassValid = Bcrypt.compareSync(
      loginUserDto.password,
      user.password,
    );

    if (!isPassValid)
      throw new RpcException({
        status: 400,
        message: 'Invalid credentials',
      });

    const { password: _, ...res } = user;

    return {
      user: res,
      token: await this.signJWT(res),
    };
  }
}
