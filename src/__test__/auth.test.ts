import express from 'express';
import authRoutes from '../auth/routes';
import { pool } from '../config/db';
import dragonflyClient from '../config/dragonfly';
import { sendOTPEmail } from '../config/mail';
import argon2 from 'argon2';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { verify } from 'crypto';

jest.mock('../config/db', () => ({
  pool: {
    query: jest.fn(),
  },
}));

jest.mock('../config/dragonfly', () => ({
  setEx: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
}));

jest.mock('../config/mail', () => ({
  sendOTPEmail: jest.fn(),
}));

jest.mock('argon2', () => ({
  hash: jest.fn().mockResolvedValue('hashed_value'),
  verify: jest.fn().mockResolvedValue(true),
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
  verify: jest.fn(),
}));

jest.mock('passport', () => ({
  authenticate: jest.fn((strategy, options, callback) => {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
      callback(null, { id: 1, username: 'testuser', email: 'test@test.com', name: 'Test User' }, null);
    };
  }),
}));

const app = express();
app.use(express.json());
app.use('/auth', authRoutes);

describe('Signup', () => {
    it('should signup a new user', async () => {
        // Mock database responses
        (pool.query as jest.Mock)
            .mockResolvedValueOnce({ rows: [] }) // username check
            .mockResolvedValueOnce({ rows: [] }) // email check
            .mockResolvedValueOnce({ rows: [{ id: 1 }] }); // insert user

        // Mock Redis setEx
        (dragonflyClient.setEx as jest.Mock).mockResolvedValue('OK');

        // Mock sendOTPEmail
        (sendOTPEmail as jest.Mock).mockResolvedValue(true);

        const res = await request(app).post('/auth/signup').send({
            username: 'testuser',
            name: 'Test User',
            email: 'test@test.com',
            password: 'Test123@' // Şifre kriterlerini karşılayan bir şifre
        });

        expect(res.statusCode).toEqual(201);
        expect(res.body).toEqual({ message: 'User successfully registered' });
    });
    it('should return 400 if username is already registered', async () => {
        (pool.query as jest.Mock).mockResolvedValueOnce({ rows: [{ id: 1 }] }); // username check

        const res = await request(app).post('/auth/signup').send({
            username: 'testuser',
            name: 'Test User',
            email: 'test@test.com',
            password: 'Test123@'
        });

        expect(res.statusCode).toEqual(400);
        expect(res.body).toEqual({ message: 'This username is already registered' });
    });
    it('should return 400 if email is already registered', async () => {
        (pool.query as jest.Mock).mockResolvedValueOnce({ rows: [] }); // username check
        (pool.query as jest.Mock).mockResolvedValueOnce({ rows: [{ id: 1 }] }); // email check

        const res = await request(app).post('/auth/signup').send({
            username: 'testuser',
            name: 'Test User',
            email: 'test@test.com',
            password: 'Test123@'
        });

        expect(res.statusCode).toEqual(400);
        expect(res.body).toEqual({ message: 'This email is already registered' });
    });
    
      it('should return 500 status and error message on server error', async () => {
    // Sunucu hatasını simüle et (örneğin, veritabanı bağlantısını geçici olarak kes)
    jest.spyOn(pool, 'query').mockRejectedValueOnce(new Error('Database connection error') as never);

    const response = await request(app)
      .post('/auth/signup')
      .send({
        username: 'testuser',
        email: 'test@example.com',
        password: 'ValidP@ssw0rd',
        name: 'Test User'
      });
    

    expect(response.status).toBe(500);
    expect(response.body).toEqual({ message: 'Server error. Please try again later.' });
  });



 
});

describe('Signup Verify',()=>{
    it('should verify user', async () => {
        // Mock database responses
        (pool.query as jest.Mock)
          .mockResolvedValueOnce({ rows: [] }) // İlk sorgu için boş sonuç
          .mockResolvedValueOnce({ rows: [{ id: 1, username: 'testuser', email: 'test@test.com', name: 'Test User' }] }); // Kullanıcı bilgileri sorgusu
    
        // Mock Dragonfly responses
        (dragonflyClient.get as jest.Mock).mockResolvedValueOnce('hashed_otp');
        (dragonflyClient.del as jest.Mock).mockResolvedValueOnce('OK');
    
        // Mock argon2 verify
        (argon2.verify as jest.Mock).mockResolvedValueOnce(true);
    
        // Mock JWT sign
        (jwt.sign as jest.Mock)
          .mockReturnValueOnce('mocked_access_token')
          .mockReturnValueOnce('mocked_refresh_token');
    
        const res = await request(app).post('/auth/signup-verify').send({
          email: 'test@test.com',
          otp: '123456'
        });
    
        expect(res.statusCode).toEqual(200);
        expect(res.body).toEqual({
          message: 'Email address has been successfully verified and logged in',
          user: { username: 'testuser', email: 'test@test.com', name: 'Test User' }
        });
    
        // Cookie'lerin ayarlandığını kontrol et
        expect(res.headers['set-cookie']).toBeDefined();
        expect(res.headers['set-cookie'][0]).toContain('access_token');
        expect(res.headers['set-cookie'][1]).toContain('refresh_token');
      });
      it('should return 400 if otp is incorrect', async () => {
        (argon2.verify as jest.Mock).mockResolvedValueOnce(false);
    
        const res = await request(app).post('/auth/signup-verify').send({
          email: 'test@test.com',
          otp: '123456'
        });
    
        expect(res.statusCode).toEqual(400);
        expect(res.body).toEqual({ message: 'Invalid OTP' });
      })
      it('should return 500 status and error message on server error', async () => {
        jest.spyOn(dragonflyClient, 'get').mockRejectedValueOnce(new Error('Redis connection error'));
        const response = await request(app)
          .post('/auth/signup-verify')
          .send({
            email: 'test@example.com',
            otp: '123456'
          });
          expect(response.status).toBe(500);
          expect(response.body).toEqual({ message: 'Server error. Please try again later.' });
      })
})

describe('Login', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should send OTP for valid login credentials', async () => {
        (passport.authenticate as jest.Mock).mockImplementation((strategy, options, callback) => {
            return (req: express.Request, res: express.Response, next: express.NextFunction) => {
                callback(null, { id: 1, username: 'testuser', email: 'test@test.com', name: 'Test User', type: 'local' }, null);
            };
        });

        (dragonflyClient.setEx as jest.Mock).mockResolvedValue('OK');
        (sendOTPEmail as jest.Mock).mockResolvedValue(true);

        const res = await request(app).post('/auth/login').send({
            email: 'test@test.com',
            password: 'Test123@'
        });

        expect(res.statusCode).toEqual(200);
        expect(res.body).toEqual({
            message: 'OTP sent',
            email: 'test@test.com'
        });
    });

    it('should return 400 for invalid credentials', async () => {
        (passport.authenticate as jest.Mock).mockImplementation((strategy, options, callback) => {
            return (req: express.Request, res: express.Response, next: express.NextFunction) => {
                callback(null, false, { message: 'Invalid email or password' });
            };
        });

        const res = await request(app).post('/auth/login').send({
            email: 'wrong@test.com',
            password: 'WrongPassword'
        });

        expect(res.statusCode).toEqual(400);
        expect(res.body).toEqual({ message: 'Invalid email or password' });
    });

    it('should return 400 for invalid input', async () => {
        const res = await request(app).post('/auth/login').send({
            email: 'notanemail',
            password: ''
        });

        expect(res.statusCode).toEqual(400);
        expect(res.body.errors).toBeDefined();
    });

    it('should return 500 for server error', async () => {
        (passport.authenticate as jest.Mock).mockImplementation((strategy, options, callback) => {
          return (req: express.Request, res: express.Response, next: express.NextFunction) => {
            const error = new Error('Database error ');
            next(error);
          };
        });
      
        const res = await request(app).post('/auth/login').send({
          email: 'test@test.com',
          password: 'Test123@'
        });
      
        expect(res.statusCode).toEqual(500);
        expect(res.body).toBeDefined();
      });
});

describe('Login Verify', () => {
    beforeEach(() => {
        jest.clearAllMocks()
        jest.resetAllMocks();
    });
 

  it('should successfully verify OTP and login user', async () => {
    (dragonflyClient.get as jest.Mock).mockResolvedValue('hashedOtp');
    (dragonflyClient.del as jest.Mock).mockResolvedValue('OK');
    (argon2.verify as jest.Mock).mockResolvedValue(true);
    (pool.query as jest.Mock).mockResolvedValue({ rows: [{ id: 1, username: 'testuser', email: 'test@test.com', name: 'Test User' }] });
    (jwt.sign as jest.Mock).mockReturnValue('mockedToken');
  
    const res = await request(app)
      .post('/auth/login-verify')
      .send({ email: 'test@test.com', otp: '123456' });
  
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({
      message: 'Login successful',
      user: { username: 'testuser', email: 'test@test.com', name: 'Test User' }
    });
  
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'][0]).toContain('access_token');
    expect(res.headers['set-cookie'][1]).toContain('refresh_token');

    
  });

  it('should return 400 for invalid email', async () => {
    const res = await request(app)
      .post('/auth/login-verify')
      .send({ email: 'invalidemail', otp: '123456' });

    expect(res.statusCode).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  it('should return 400 for invalid OTP format', async () => {
    const res = await request(app)
      .post('/auth/login-verify')
      .send({ email: 'test@test.com', otp: '12345' });

    expect(res.statusCode).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  it('should return 400 for expired or invalid OTP', async () => {
    (dragonflyClient.get as jest.Mock).mockResolvedValue(null);

    const res = await request(app)
      .post('/auth/login-verify')
      .send({ email: 'test@test.com', otp: '123456' });

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ message: 'OTP expired or invalid' });
  });

  it('should return 400 for incorrect OTP', async () => {
    (dragonflyClient.get as jest.Mock).mockResolvedValue('hashedOtp');
    (argon2.verify as jest.Mock).mockResolvedValue(false);

    const res = await request(app)
      .post('/auth/login-verify')
      .send({ email: 'test@test.com', otp: '123456' });

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({ message: 'Invalid OTP' });
  });

  it('should return 500 for server error', async () => {
    (dragonflyClient.get as jest.Mock).mockRejectedValue(new Error('Database error '));

    const res = await request(app)
      .post('/auth/login-verify')
      .send({ email: 'test@test.com', otp: '123456' });

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ message: 'Server error' });
  });
});

describe('Resend OTP', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      jest.resetAllMocks();
    });
  
    it('should resend OTP for signup', async () => {
      (dragonflyClient.get as jest.Mock).mockResolvedValue(null);
      (dragonflyClient.setEx as jest.Mock).mockResolvedValue('OK');
      (sendOTPEmail as jest.Mock).mockResolvedValue(true);
      (argon2.hash as jest.Mock).mockResolvedValue('hashedOtp');
  
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'test@test.com', type: 'signup' });
  
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ message: 'OTP sent to your email.' });
    });
  
    it('should resend OTP for login', async () => {
      (dragonflyClient.get as jest.Mock).mockResolvedValue(null);
      (dragonflyClient.setEx as jest.Mock).mockResolvedValue('OK');
      (sendOTPEmail as jest.Mock).mockResolvedValue(true);
      (argon2.hash as jest.Mock).mockResolvedValue('hashedOtp');
  
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'test@test.com', type: 'login' });
  
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ message: 'OTP sent to your email.' });
    });
  
    it('should resend OTP for forgot password', async () => {
      (dragonflyClient.get as jest.Mock).mockResolvedValue(null);
      (dragonflyClient.setEx as jest.Mock).mockResolvedValue('OK');
      (sendOTPEmail as jest.Mock).mockResolvedValue(true);
      (argon2.hash as jest.Mock).mockResolvedValue('hashedOtp');
  
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'test@test.com', type: 'forgotpassword' });
  
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ message: 'OTP sent to your email.' });
    });
  
    it('should return 400 for invalid email', async () => {
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'invalid-email', type: 'signup' });
  
      expect(res.statusCode).toBe(400);
      expect(res.body.errors).toBeDefined();
    });
  
    it('should return 400 for invalid type', async () => {
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'test@test.com', type: 'invalid-type' });
  
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ message: 'Invalid type.' });
    });
  
    it('should return 400 if OTP already sent', async () => {
      (dragonflyClient.get as jest.Mock).mockResolvedValue('existingOtp');
  
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'test@test.com', type: 'signup' });
  
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ message: 'OTP already sent. Please wait for 3 minutes or use the current OTP.' });
    });
  
    it('should return 500 for server error', async () => {
      (dragonflyClient.get as jest.Mock).mockRejectedValue(new Error('Database error'));
  
      const res = await request(app)
        .post('/auth/resend-otp')
        .send({ email: 'test@test.com', type: 'signup' });
  
      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual({ message: 'Server error. Please try again later.' });
    });
  });

  describe('Forgot Password Part 1', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });
    it('should send OTP for valid email', async () => {
      (pool.query as jest.Mock).mockResolvedValueOnce({ rows: [{ id: 1, email: 'test@test.com', password: 'hashedPassword', type: 'local' }] });
      (dragonflyClient.setEx as jest.Mock).mockResolvedValueOnce('OK');
      (sendOTPEmail as jest.Mock).mockResolvedValueOnce(true);
      (argon2.hash as jest.Mock).mockResolvedValue('hashedOtp');
      (jwt.sign as jest.Mock).mockReturnValue('part1Hash');

      const res = await request(app).post('/auth/forgotpassword-part1').send({
        email: 'test@test.com'
      });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toEqual({ message: 'OTP sent', part1Hash: 'part1Hash' });
    });
  
    it('should return 400 for invalid email', async () => {
      const res = await request(app)
        .post('/auth/forgotpassword-part1')
        .send({ email: 'invalid-email' });
  
      expect(res.statusCode).toBe(400);
      expect(res.body.errors).toBeDefined();
    });
  
    it('should return 404 if user not found', async () => {
      (pool.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      const res = await request(app).post('/auth/forgotpassword-part1').send({
        email: 'nonexistent@test.com'
      });
  
      expect(res.statusCode).toBe(404);
      expect(res.body).toEqual({ message: 'User not found.' });
    });
  
    it('should return 500 for server error', async () => {
      (pool.query as jest.Mock).mockRejectedValue(new Error('Database error'));
  
      const res = await request(app)
        .post('/auth/forgotpassword-part1')
        .send({ email: 'test@test.com' });
  
      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual({ message: 'Server error. Please try again later.' });
    });
  });

  describe('Forgot Password Part 2', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });
  
    it('should verify OTP and return part2Hash', async () => {
      const mockEmail = 'test@test.com';
      (jwt.verify as jest.Mock).mockReturnValue({ email: mockEmail });
      (dragonflyClient.get as jest.Mock).mockResolvedValue('hashedOtp');
      (argon2.verify as jest.Mock).mockResolvedValue(true);
      (jwt.sign as jest.Mock).mockReturnValue('part2Hash');
      (dragonflyClient.del as jest.Mock).mockResolvedValue('OK');
  
      const res = await request(app)
        .post('/auth/forgotpassword-part2')
        .send({ part1Hash: 'validPart1Hash', otp: '123456' });
  
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ message: 'OTP verified', part2Hash: 'part2Hash' });
    });
  

  
    it('should return 401 for invalid part1Hash', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });
  
      const res = await request(app)
        .post('/auth/forgotpassword-part2')
        .send({ part1Hash: 'invalidPart1Hash', otp: '123456' });
  
      expect(res.statusCode).toBe(401);
      expect(res.body).toEqual({ message: 'Invalid part1Hash' });
    });
  
    it('should return 401 for invalid OTP', async () => {
      const mockEmail = 'test@test.com';
      (jwt.verify as jest.Mock).mockReturnValue({ email: mockEmail });
      (dragonflyClient.get as jest.Mock).mockResolvedValue('hashedOtp');
      (argon2.verify as jest.Mock).mockResolvedValue(false);
  
      const res = await request(app)
        .post('/auth/forgotpassword-part2')
        .send({ part1Hash: 'validPart1Hash', otp: '123456' });
  
      expect(res.statusCode).toBe(401);
      expect(res.body).toEqual({ message: 'Invalid OTP.' });
    });
  
    it('should return 401 for expired OTP', async () => {
      const mockEmail = 'test@test.com';
      (jwt.verify as jest.Mock).mockReturnValue({ email: mockEmail });
      (dragonflyClient.get as jest.Mock).mockResolvedValue(null);
  
      const res = await request(app)
        .post('/auth/forgotpassword-part2')
        .send({ part1Hash: 'validPart1Hash', otp: '123456' });
  
      expect(res.statusCode).toBe(401);
      expect(res.body).toEqual({ message: 'Invalid OTP.' });
    });
  
    it('should return 500 for server error', async () => {
        jest.spyOn(dragonflyClient, 'get').mockRejectedValueOnce(new Error('Database error'));
      
  
      const res = await request(app)
        .post('/auth/forgotpassword-part2')
        .send({ part1Hash: 'validPart1Hash', otp: '123456' });
  
      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual({ message: 'Server error. Please try again later.' });
    });
    describe('Forgot Password Part 3', () => {
        beforeEach(() => {
          jest.clearAllMocks();
          process.env.JWT_SECRET = 'test_secret';
          process.env.JWT_ISSUER = 'test_issuer';
          process.env.JWT_AUDIENCE = 'test_audience';
        });
      
        it('should update password successfully', async () => {
          const mockEmail = 'test@test.com';
          (jwt.verify as jest.Mock).mockReturnValue({ email: mockEmail, iss: 'test_issuer', aud: 'test_audience' });
          (pool.query as jest.Mock).mockResolvedValueOnce({ rows: [{ email: mockEmail }] });
          (pool.query as jest.Mock).mockResolvedValueOnce({ rowCount: 1 });
          (argon2.hash as jest.Mock).mockResolvedValue('hashedPassword');
      
          const res = await request(app)
            .post('/auth/forgotpassword-part3')
            .send({ part2Hash: 'validPart2Hash', newPassword: 'NewPassword123' });
      
          expect(res.statusCode).toBe(200);
          expect(res.body).toEqual({ message: 'Password updated' });
        });
      
        it('should return 400 for invalid input', async () => {
          const res = await request(app)
            .post('/auth/forgotpassword-part3')
            .send({ part2Hash: 'validPart2Hash', newPassword: 'weak' });
      
          expect(res.statusCode).toBe(400);
          expect(res.body.errors).toBeDefined();
        });
      
        it('should return 401 for invalid part2Hash', async () => {
          (jwt.verify as jest.Mock).mockImplementation(() => {
            throw new Error('Invalid token');
          });
      
          const res = await request(app)
            .post('/auth/forgotpassword-part3')
            .send({ part2Hash: 'invalidPart2Hash', newPassword: 'NewPassword123' });
      
          expect(res.statusCode).toBe(401);
          expect(res.body).toEqual({ message: 'Invalid part2Hash' });
        });
      
        it('should return 401 for invalid token issuer or audience', async () => {
          (jwt.verify as jest.Mock).mockReturnValue({ email: 'test@test.com', iss: 'wrong_issuer', aud: 'wrong_audience' });
      
          const res = await request(app)
            .post('/auth/forgotpassword-part3')
            .send({ part2Hash: 'validPart2Hash', newPassword: 'NewPassword123' });
      
          expect(res.statusCode).toBe(401);
          expect(res.body).toEqual({ message: 'Invalid token.' });
        });
      
        it('should return 404 if user not found', async () => {
          (jwt.verify as jest.Mock).mockReturnValue({ email: 'test@test.com', iss: 'test_issuer', aud: 'test_audience' });
          (pool.query as jest.Mock).mockResolvedValue({ rows: [] });
      
          const res = await request(app)
            .post('/auth/forgotpassword-part3')
            .send({ part2Hash: 'validPart2Hash', newPassword: 'NewPassword123' });
      
          expect(res.statusCode).toBe(404);
          expect(res.body).toEqual({ message: 'User not found.' });
        });
      
        it('should return 500 for server error', async () => {
          (jwt.verify as jest.Mock).mockReturnValue({ email: 'test@test.com', iss: 'test_issuer', aud: 'test_audience' });
          (pool.query as jest.Mock).mockRejectedValue(new Error('Database error'));
      
          const res = await request(app)
            .post('/auth/forgotpassword-part3')
            .send({ part2Hash: 'validPart2Hash', newPassword: 'NewPassword123' });
      
          expect(res.statusCode).toBe(500);
          expect(res.body).toEqual({ message: 'Server error. Please try again later.' });
        });
      });
  });
  describe('Signout', () => {
    beforeEach(() => {
      jest.clearAllMocks();
      jest.resetAllMocks();
    });
  
   
  
    it('should return 200 even if not logged in', async () => {
      const res = await request(app).post('/auth/signout');
  
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ message: 'Signout successful' });
    });
  });