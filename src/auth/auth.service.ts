import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, UpdateAuthDto, RegisterUserDto, LoginDto, } from './dto';
import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor( 
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {} 

  async create(createUserDto: CreateUserDto):Promise<User> {
    
    try {     
      // 1- Encriptar la contraseña
      const { password, ...UserData } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...UserData
      });
      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} is already registered`);
      }
      throw new InternalServerErrorException('Something terrible happen');
    }
  }

  async register( registerUserDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerUserDto );
    console.log ('user: ', user);

    return {
      user: user,
      token: this.getJwtToken( { id: user._id } )
    }
  }

  async login( loginDto: LoginDto):Promise<LoginResponse> { 
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    // si no existe el usuario
    if ( !user ) {
      throw new UnauthorizedException('Invalid credentials email');
    }
    // comparo con la contraseña encriptada
    if ( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException('Invalid credentials password');
    }

    const { password:_,...rest  } = user.toJSON();

    return { 
      user: rest, 
      token: this.getJwtToken( { id: user.id } )
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( userId: string ) { 
    const user = await this.userModel.findById( userId );
    const { password:_, ...rest } = user.toJSON();

    return rest;
  }

  getJwtToken ( payload: JwtPayload ) { 
    const token = this .jwtService.sign( payload );
    console.log ( 'token: ', token );
    return token;
  }

  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateAuthDto: UpdateAuthDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }
}
