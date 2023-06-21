package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTUtils {

    //hash(abc)-->jflkadsflkads-->abc ye donusturulemez
    //jwt token: header + payload(userla ilgili bilgiler) + signature(secret ile imza)

    private long jwtExpirationTime=86400000; //24*60*60*1000

    private String secretKey="techpro";

    //*********************** 1-JWT token generate ***********************
    public String generateToken(Authentication authentication){
        UserDetailsImpl userDetails =(UserDetailsImpl) authentication.getPrincipal(); //login olmus user(authenticated)

        //login olan userin username ini token icine koyalim
        return Jwts.builder()  //jwt olusturucuyu saglar
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date()) //system.currentTimeMillis()
                .setExpiration(new Date(new Date().getTime() + jwtExpirationTime))
                .signWith(SignatureAlgorithm.HS512,secretKey) //hashleme ile tek yonlu sifreleme, karsilastirmada kullanilir
                .compact(); //ayarlari tamamlar, token olusturur.
    }

    //*********************** 2-JWT token validate ***********************
    public boolean validateToken(String token){

        try {
            Jwts.parser() //ayristirici
                    .setSigningKey(secretKey) //bu anahtar ile karsilastir
                    .parseClaimsJws(token); //imzalar uyumlumu ise, JWT gecerli

            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }

    //3-JWT tokendan username alma
    public String getUsernameFromJwtToken(String token){
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token) //dogrulanmis tokenin claimslerini dondurur
                .getBody()
                .getSubject(); //username
    }



}
