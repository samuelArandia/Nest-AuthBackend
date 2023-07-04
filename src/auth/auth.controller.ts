import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { CreateUserDto, RegisterUserDto, LoginDto, UpdateAuthDto } from './dto';
import { AuthService } from './auth.service';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login-response';
@Controller('auth')
export class AuthController {

  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    console.log ('createUserDto: ', createUserDto);
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login( @Body() loginDto: LoginDto) { 
    return this.authService.login( loginDto );
  }

  @Post('/register')
  register ( @Body() registerUserDto: RegisterUserDto ) {
    return this.authService.register( registerUserDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req: Request) {
    // const user = req['user'];
    // return user;
    return this.authService.findAll();
  }

  // LoginResponse
  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken( @Request() req: Request): LoginResponse { 
    const user = req['user'] as User;
    return {
      user: user,
      token: this.authService.getJwtToken( { id: user._id } )
    }
  }


  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}
