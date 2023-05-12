import { IsNotEmpty, IsString, Length, Validate } from 'class-validator';
import { isEmail, isPhoneNumber } from 'class-validator';

export class SignInAuthDto {
  @IsNotEmpty()
  @IsString()
  @Validate((value: string) => {
    if (!isEmail(value) && !isPhoneNumber(value)) {
      throw new Error('Invalid email or phone number');
    }
  })
  public emailOrPhoneNumber: string;

  @IsNotEmpty()
  @IsString()
  @Length(8, 50, { message: 'Password has to be between 8 and 50 characters' })
  public password: string;
}
