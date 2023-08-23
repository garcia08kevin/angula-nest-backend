import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request, ParseIntPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UpdateAuthDto, LoginDto, CreateUserDto ,RegisterUserDto } from './dto';
import { AuthGuard } from './auth.guard';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {    
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto){
    return this.authService.login(loginDto);
  }

  @Post('/email-exist')
  emailExist(@Body() validation:{email: string}){
    return this.authService.emailExist(validation.email);
  }

  @Post('/register')
  register(@Body() registerUserDto: RegisterUserDto){
    return this.authService.register(registerUserDto);
  }
  @UseGuards(AuthGuard)
  @Get()
  findAll(@Request() req:Request) {
    console.log(req['user']);
    return this.authService.findAll();
  }

  @UseGuards(AuthGuard)
  @Get('/check-token')
  checkToken(@Request() req:Request){
    const user = req['user'];
    return this.authService.checkToken(user);
  }

  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: string) {
    return this.authService.findOne(id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
