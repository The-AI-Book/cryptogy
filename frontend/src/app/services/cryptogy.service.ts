import { Injectable } from "@angular/core";
import { Router } from "@angular/router";
import { Subject } from "rxjs";
import { environment } from "src/environments/environment";
import { HttpClient } from "@angular/common/http";
import { Crypto } from "../models/crypto.model";

@Injectable({ providedIn: 'root' })
export class CryptogyService {
    endpoint = environment.endpoint;
    constructor(private http: HttpClient, private router: Router) {}

    get_random_key(
        cipher: string,
        keyLength: string, 
        numPartitions: string
    ){
        const CryptoData: Crypto = {
           cipher: cipher,
           keyLength: keyLength,
           key: "",
           cleartext: "",
           ciphertext: "",
           keyStream: "", 
           numPartitions: numPartitions, 
        }
        return this.http.post(this.endpoint + "/api/generate_random_key", CryptoData);
    }

    encrypt(
        key: string, 
        cipher: string, 
        cleartext: string,
        keyLength: string, 
        numPartitions: string
    ){
        const CryptoData: Crypto = {
            key: key,
            cipher: cipher, 
            cleartext: cleartext, 
            keyLength: keyLength, 
            ciphertext: "", 
            keyStream: "", 
            numPartitions: numPartitions, 
        }
        console.log(CryptoData);
        return this.http.post(this.endpoint + "/api/encrypt", CryptoData);
    }

    encrypt_image(
        file: File
    ){
        const data = new FormData();
        data.append("files", file, file.name);
        return this.http.post(this.endpoint + "/api/encrypt_image", data)
    }


    decrypt(
        key: string, 
        cipher: string, 
        ciphertext: string, 
        keyLength: string, 
        keyStream: string, 
        numPartitions: string
    ){
        const CryptoData: Crypto = {
            key: key, 
            cipher: cipher, 
            ciphertext: ciphertext, 
            keyLength: keyLength, 
            keyStream: keyStream, 
            cleartext: "", 
            numPartitions: numPartitions, 
        }
        console.log(CryptoData);
        return this.http.post(this.endpoint + "/api/decrypt", CryptoData);
    }
    analize(
        cipher: string,
        ciphertext: string,
        cleartext: string, 
        numPartitions: string
    ){
        const CryptoData: Crypto = {
            cipher: cipher, 
            ciphertext: ciphertext, 
            cleartext: cleartext,
            keyStream: "", 
            key: "", 
            keyLength: "", 
            numPartitions: numPartitions, 
        }
        return this.http.post(this.endpoint + "/api/analyze", CryptoData);
    }
}