import org.apache.commons.lang3.ArrayUtils;

import java.util.ArrayList;
import java.util.Vector;

public class DES {
    private char[] ciphertext=new char[64];
    private char[] key;//密钥
    private int key_time=0;//循环左移的次数
    private int plaintext_time=0;//明文循环异或次数
    private char[] pc_1;//pc_1置换结果
    private char[] Ipl;//经过IP置换的明文左半部分
    private char[] Ipr;//经过置换的明文右半部分
    private char[] E_Box;//ebox扩展后的48位明文,但是为了保存ipr方便其作为下一轮ipl，故本轮的ebox会充当ipr
    private char[] plaintext =new char[64];//明文
    private ArrayList<Character[]> L=new ArrayList<>();//用于储存16轮移动的左密钥块
    private ArrayList<Character[]> R=new ArrayList<>();//用于储存16轮移动的右密钥块
    private ArrayList<Character[]>keys=new ArrayList<>();//用于储存16个子密钥
    public void setKey(String s ) {
        if(s.length()==64){
        key=s.toCharArray();}
    }
    public void PC_1(){

        String l1=String.copyValueOf(key,0,32);
        String l2=String.copyValueOf(key,32,32);
        char[] c1=l1.toCharArray();
        char[] c2=l2.toCharArray();
        Vector<Character> characters=new Vector<>();
        for(int i=0;i<32;i++){
            characters.add(c1[i]);
        }
        for (int i=0;i<32;i++){
            characters.add(c2[i]);
        }
        char[] Pc_1Table={57,49,41,33,25,17,9,1,58,50,42,34,26,18,
                          10,2,59,51,43,35,27,19,11,3,60,52,44,36,
                          63,55,47,39,31,23,15,7,62,54,46,38,30,22,
                          14,6,61,53,45,37,29,21,13,5,28,10,12,4};//pc-1置换表
        char[] c3=new char[56];
        for (int i=0;i<56   ;i++){
            c3[i]=characters.get(Pc_1Table[i]);
        }
        pc_1=c3;
    }//PC-1
    public void splitPc_1(){
    char[] L0=new char[28];
    char[] R0=new char[28];
    for (int i=0;i<28;i++){
        L0[i]=pc_1[i];
        R0[i]=pc_1[i+28];
    }

    L.add(ArrayUtils.toObject(L0));
    R.add(ArrayUtils.toObject(R0));


    }//将pc-1置换后的结果切为L0R0两个矩阵并储存在L,R两个列表中。
    public void liftShift(){
        Character[] l= L.get(L.size()-1);
        Character[] r=R.get(R.size()-1);
        Character[] l1=new Character[28];
        Character[] r1=new Character[28];//储存处理后的左右密钥
        char[] shift1=new char[]{1,2,3,4,5,6,7,8,9,10,
                                  11,12,13,14,15,16,17,18,19,
                                  20,21,22,23,24,25,26,27,0};
        char[] shift2=new char[]{2,3,4,5,6,7,8,9,10,11,12,13,14,
                                15,16,17,18,19,20,21,22,23,24,25,
                                26,27,0,1};
        if(key_time==1 || key_time==2||key_time ==9|| key_time==16){
            for(int i=0;i<28;i++){
                l1[i]=l[shift1[i]];
                r1[i]=r[shift1[i]];
            }
        }//只左移一位时
        else{
            for(int i=0;i<28;i++){
                l1[i]=l[shift2[i]];
                r1[i]=r[shift2[i]];
            }
        }//左移两位时
        key_time++;
        L.add(l1);
        R.add(r1);


    }//循环左移生成子密钥
    public void PC_2(){
        Character[] l=L.get(L.size()-1);
        Character[] r=R.get(R.size()-1);
        char[] pc_2=new char[] {
                14,17,11,24,1,5,
                3,28,15,6,21,10,
                23,19,12,4,26,8,
                16,7,27,20,13,2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32};
        Character[] key1=new Character[56];
        for(int i=0;i<28;i++){
            key1[i]=l[i];
        }
        for(int j=0;j<28;j++){
            key1[j+28]=r[j];
        }
        Character[] key2=new Character[48];//pc-2置换后的密钥
        for(int i=0;i<48;i++){
            key2[i]=key1[pc_2[i]-1];
        }//PC-2置换过程
        keys.add(key2);//储存置换后的密钥
    }//PC-2
    public void IP(){
        char[] IPBox=new char[]{58,50,42,34,26,18,10,2,
                                60,52,44,36,28,20,12,4,
                                62,54,46,38,30,22,14,6,
                                64,56,48,40,32,24,16,8,
                                57,49,41,33,25,17,9,1,
                                59,51,43,35,27,19,11,3,
                                61,53,45,37,29,21,13,5,
                                63,55,47,39,31,23,15,7};
        char[] ip=new char[64];
        for(int i=0;i<64;i++){
            ip[i]=plaintext[IPBox[i]-1];
        }
        char[] ipl=new char[32];
        char[] ipr=new char[32];

        for (int i=0;i<32;i++){
            ipl[i]=ip[i];
            ipr[i]=ip[i+32];
        }
        Ipl=ipl;
        Ipr=ipr;




    }//明文初始置换
    public void Ebox(){
         char[] Ebox=new char[]{
                 32,1,2,3,4,5,
                 4,5,6,7,8,9,
                 8,9,10,11,12,13,
                 12,13,14,15,16,17,
                 16,17,18,19,20,21,
                 20,21,22,23,24,25,
                 24,25,26,27,28,29,
                28,29,30,31,32,1};
         char[] s=new char[48];
         for(int  i=0;i<48;i++){
            s[i]=Ipr[Ebox[i]-1];
         }
         E_Box=s;
    }//Ebox扩展
    public void KPxor(){
        char[] Xor=new char[48];
        char[] RightKey=ArrayUtils.toPrimitive(keys.get(plaintext_time));
        for(int i=0 ;i<48;i++){
            Xor[i]=String.valueOf(E_Box[i]^RightKey[i]).charAt(0);

        }
        E_Box=Xor;

    }//经过Ebox扩展的明文和子密钥执行异或
    public void S_Box(){
        char[][] sbox1=new char[][]{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};
        char[][] sbox2=new char[][]{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                                    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                                    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};
        char[][] sbox3=new char[][]{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                                    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                                    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};
        char[][] sbox4=new char[][]{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                                    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};
        char[][] sbox5=new char[][]{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};
        char[][] sbox6=new char[][]{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                                    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};
        char[][] sbox7=new char[][]{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};
        char[][] sbox8=new char[][]{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
        ArrayList<Character[]>arrayList=new ArrayList<>();

        for(int i=0;i<8;i++){
            Character[]  block=new Character[6];
            for(int j=0;j<6;j++){
                block[j]=E_Box[6*i+j];
                if(j==5){
                    arrayList.add(block);
                }
        }
        }//将明文右半部分分为8组存入列表

        ArrayList<Integer> FirstLast=new ArrayList<>();//用于储存首末位
        ArrayList<Integer> Mid=new ArrayList<>();//储存中间位
        for(int i=0;i<8;i++){
            Character[] characters= arrayList.get(i);
            char[] chars=ArrayUtils.toPrimitive(characters);
            String FL=String.copyValueOf(chars,0,1);
            FL+=String.copyValueOf(chars,5,1);
            Integer integer1=Integer.valueOf(FL,2);
            String M=String.copyValueOf(chars,1,4);
            Integer integer2=Integer.valueOf(M,2);
            FirstLast.add(integer1);
            Mid.add(integer2);
        }//将二进制字符串转化为十进制整数存入列表
        ArrayList<Integer> result=new ArrayList<>();//置换后结果
        result.add((sbox1[FirstLast.get(0)][Mid.get(0)])-'0');
        result.add((sbox2[FirstLast.get(1)][Mid.get(1)])-'0');
        result.add((sbox3[FirstLast.get(2)][Mid.get(2)])-'0');
        result.add((sbox4[FirstLast.get(3)][Mid.get(3)])-'0');
        result.add((sbox5[FirstLast.get(4)][Mid.get(4)])-'0');
        result.add((sbox6[FirstLast.get(5)][Mid.get(5)])-'0');
        result.add((sbox7[FirstLast.get(6)][Mid.get(6)])-'0');
        result.add((sbox8[FirstLast.get(7)][Mid.get(7)])-'0');
       //获取8个sbox置换结果
        char[] chars1=new char[48];
        for(int i=0;i<8;i++){
            char [] chars2=Integer.toBinaryString(result.get(i)).toCharArray();
            for(int j=0;j<6;j++){
                chars1[i*6+j]=chars2[j];
            }
        }
        E_Box=chars1;
    }//Sbox置换
    public void P_Box(){
        char[] p_box={
                16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
                2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
        };
        char[] After_pbox=new char[32];
        for(int i=0;i<32;i++){
            After_pbox[i]=E_Box[p_box[i]-1];
        }
        E_Box=After_pbox;

    }//Pbox置换
    public  void  LRxor(){
        char[] xor=new char[32];
        for(int i=0;i<32;i++){
            xor[i]=String.valueOf(E_Box[i]^Ipl[i]).charAt(0);

        }
        plaintext_time++;
        if(plaintext_time!=16){
        Ipl=Ipr;
        Ipr=xor;}else{
            Ipr=xor;
        }

    }//明文左部分和处理后的右部分异或
    public void FP(){
      char[] fp=new char[]{
              40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
              38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
              36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
              34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
      char[] f_text=new char[64];
      for (int i=0;i<32;i++){
          f_text[i]=Ipl[i];
      }
      for (int j=0;j<32;j++){
          f_text[32+j]=Ipr[j];
      }
      char[] chiphertext1=new char[64];
      for(int i=0;i<64;i++){
          chiphertext1[i]=f_text[fp[i]-1];
      }
      ciphertext=chiphertext1;
    }//最终置换
    public char[] getKey() {
        return key;
    }
    public void setPlaintext(String plaintext) {
        this.plaintext = plaintext.toCharArray();
    }

    public char[] getCiphertext() {
        return ciphertext;
    }

    public static void main(String[] args){
        DES des=new DES();
        des.setKey("1101001100110100010101110111100110011011101111001101111111110001");
        des.setPlaintext("0000000100100011010001010110011110001001101010111100110111101111");
        des.PC_1();
        des.splitPc_1();
        for(int i=0;i<16;i++){
            des.liftShift();
            des.PC_2();
        }
        des.IP();
        for(int i=0;i<16;i++){
            des.Ebox();
            des.KPxor();
            des.S_Box();
            des.P_Box();
            des.LRxor();
        }
        des.FP();
        System.out.println(String.valueOf(des.getCiphertext()));



    }
}
