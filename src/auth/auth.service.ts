import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { User } from './entities/user.entity';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interface/jwt.payload.interface';
import { LoginResponse } from './interface/login-response.interface';
import { UpdateAuthDto, LoginDto, CreateUserDto, RegisterUserDto } from './dto';
import * as request from 'supertest';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      const createUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });
      await createUser.save()
      const { password: _, ...user } = createUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`El correo ${createUserDto.email} ya existe`)
      }
      throw new InternalServerErrorException('Algo salio mal')
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('El correo no esta registrado');
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('La contraseña es incorrecta');
    }
    const { password: _, ...userData } = user.toJSON();
    return {
      user: userData,
      token: await this.getJwtToken({ id: user.id })
    };
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUserDto);
    return {
      user: user,
      token: await this.getJwtToken({ id: user._id })
    }
  }


  async emailExist(email: string): Promise<boolean> {
    const validation = await this.userModel.findOne({ email });
    if (!validation) return false;  
    return true;
  }

  private async getJwtToken(payload: JwtPayload) {
    const token = await this.jwtService.signAsync(payload)
    return token
  }

  async findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findOne(id: string) {
    const found = await this.userModel.findById(id);
    if (!found) {
      throw new UnauthorizedException('No se encontro el usuario');
    }
    const { password, ...user } = found.toJSON();
    return user;
  }

  async findUserById(id: string) {
    const userData = await this.userModel.findById(id);
    const { password, ...user } = userData.toJSON();
    return user;
  }

  async checkToken(user: User): Promise<LoginResponse> {
    try {
      return {
        user: user,
        token: await this.getJwtToken({ id: user._id })
      }
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  async validateToken(token: string, request?: any): Promise<boolean> {
    try {
      const payload = await this.jwtService.verifyAsync(
        token, { secret: `${process.env.SECRET_KEY}` }
      );
      const user = await this.findUserById(payload.id);
      if (!user) { throw new UnauthorizedException('No se encontro el usuario'); }
      if (!user.isActive) { throw new UnauthorizedException('El usuario no esta activo'); }
      if (request) request['user'] = user;
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
