/*     */ package com.bss.controller;
/*     */ 
/*     */ import cn.hutool.core.util.RandomUtil;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.Poster;
/*     */ import com.bss.entity.SystemConfig;
/*     */ import com.bss.service.impl.MemberServiceImpl;
/*     */ import com.bss.service.impl.PosterServiceImpl;
/*     */ import com.bss.service.impl.SystemConfigServiceImpl;
/*     */ import com.bss.utils.ImageConverter;
/*     */ import com.bss.utils.QRCodeGenerator;
/*     */ import com.bss.utils.QRCodeGeneratorWithColor;
/*     */ import com.google.zxing.WriterException;
/*     */ import java.awt.AlphaComposite;
/*     */ import java.awt.Color;
/*     */ import java.awt.Graphics2D;
/*     */ import java.awt.RenderingHints;
/*     */ import java.awt.geom.RoundRectangle2D;
/*     */ import java.awt.image.BufferedImage;
/*     */ import java.awt.image.ImageObserver;
/*     */ import java.io.ByteArrayOutputStream;
/*     */ import java.io.DataInputStream;
/*     */ import java.io.IOException;
/*     */ import java.net.URL;
/*     */ import javax.annotation.Resource;
/*     */ import javax.imageio.ImageIO;
/*     */ import javax.servlet.ServletOutputStream;
/*     */ import javax.servlet.http.HttpServletRequest;
/*     */ import javax.servlet.http.HttpServletResponse;
/*     */ import javax.servlet.http.HttpSession;
/*     */ import org.springframework.http.HttpHeaders;
/*     */ import org.springframework.http.HttpStatus;
/*     */ import org.springframework.http.MediaType;
/*     */ import org.springframework.http.ResponseEntity;
/*     */ import org.springframework.stereotype.Controller;
/*     */ import org.springframework.util.MultiValueMap;
/*     */ import org.springframework.web.bind.annotation.GetMapping;
/*     */ import org.springframework.web.bind.annotation.RequestMapping;
/*     */ import org.springframework.web.bind.annotation.RequestParam;
/*     */ 
/*     */ 
/*     */ @Controller
/*     */ @RequestMapping({"/draw"})
/*     */ public class DrawController
/*     */ {
/*     */   @Resource
/*     */   private PosterServiceImpl posterService;
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */   @Resource
/*     */   private SystemConfigServiceImpl systemConfigService;
/*  54 */   private static int WIDTH = 540;
/*  55 */   private static int HEIGHT = 960;
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/poster"})
/*     */   public void poster(String appid, Long merchant, Long uid, Integer pid, String secret, HttpServletRequest request, HttpServletResponse response) throws IOException {
/*  65 */     HttpSession session = request.getSession();
/*     */     
/*  67 */     session.setMaxInactiveInterval(120);
/*     */     
/*  69 */     session.setAttribute("currentProviderId", merchant);
/*     */     
/*  71 */     Poster poster = (Poster)this.posterService.getOne((Wrapper)(new QueryWrapper()).eq("id", pid));
/*     */     
/*  73 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/*  75 */     response.setContentType("image/jpeg");
/*  76 */     ServletOutputStream sos = response.getOutputStream();
/*     */     
/*  78 */     response.setHeader("Pragma", "No-cache");
/*  79 */     response.setHeader("Cache-Control", "no-cache");
/*  80 */     response.setDateHeader("Expires", 0L);
/*     */     
/*  82 */     BufferedImage image = new BufferedImage(poster.getImgW().intValue(), poster.getImgH().intValue(), 1);
/*     */     
/*  84 */     Graphics2D g = image.createGraphics();
/*     */     
/*  86 */     g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
/*     */     
/*  88 */     URL imageUrl = new URL(poster.getMainImage());
/*  89 */     DataInputStream imageInputStream = new DataInputStream(imageUrl.openStream());
/*  90 */     BufferedImage imageBufferedImage = ImageIO.read(imageInputStream);
/*  91 */     imageInputStream.close();
/*  92 */     g.drawImage(imageBufferedImage, 0, 0, poster.getImgW().intValue(), poster.getImgH().intValue(), null);
/*     */ 
/*     */     
/*  95 */     Color colorByHex = Color.decode(poster.getQrColor());
/*  96 */     int color_r = colorByHex.getRed();
/*  97 */     int color_g = colorByHex.getGreen();
/*  98 */     int color_b = colorByHex.getBlue();
/*     */ 
/*     */     
/* 101 */     URL qrcodeUrl = new URL(systemConfig.getServiceUrl() + "/service/getUnlimitedQRCode?appid=" + appid + "&uid=" + uid + "&color_r=" + color_r + "&color_g=" + color_g + "&color_b=" + color_b + "&is_hyaline=" + poster.getIsHyaline());
/* 102 */     DataInputStream qrcodeInputStream = new DataInputStream(qrcodeUrl.openStream());
/* 103 */     BufferedImage qrcodeBufferedImage = ImageIO.read(qrcodeInputStream);
/* 104 */     qrcodeInputStream.close();
/* 105 */     g.drawImage(qrcodeBufferedImage, poster.getQrX().intValue(), poster.getQrY().intValue(), poster.getQrW().intValue(), poster.getQrH().intValue(), null);
/* 106 */     g.dispose();
/*     */ 
/*     */     
/* 109 */     ByteArrayOutputStream bos = new ByteArrayOutputStream();
/*     */     
/* 111 */     ImageIO.write(image, "JPEG", bos);
/*     */     
/* 113 */     byte[] buf = bos.toByteArray();
/* 114 */     response.setContentLength(buf.length);
/* 115 */     sos.write(buf);
/* 116 */     bos.close();
/* 117 */     sos.close();
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/poster_app"})
/*     */   public void poster_app(Long uid, Integer pid, String secret, HttpServletRequest request, HttpServletResponse response) throws IOException {
/* 128 */     Poster poster = (Poster)this.posterService.getOne((Wrapper)(new QueryWrapper()).eq("id", pid));
/*     */     
/* 130 */     SystemConfig systemConfig = (SystemConfig)this.systemConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 132 */     response.setContentType("image/jpeg");
/* 133 */     ServletOutputStream sos = response.getOutputStream();
/*     */     
/* 135 */     response.setHeader("Pragma", "No-cache");
/* 136 */     response.setHeader("Cache-Control", "no-cache");
/* 137 */     response.setDateHeader("Expires", 0L);
/*     */     
/* 139 */     BufferedImage image = new BufferedImage(poster.getImgW().intValue(), poster.getImgH().intValue(), 1);
/*     */     
/* 141 */     Graphics2D g = image.createGraphics();
/*     */     
/* 143 */     g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
/*     */     
/* 145 */     URL imageUrl = new URL(poster.getMainImage());
/* 146 */     DataInputStream imageInputStream = new DataInputStream(imageUrl.openStream());
/* 147 */     BufferedImage imageBufferedImage = ImageIO.read(imageInputStream);
/* 148 */     imageInputStream.close();
/* 149 */     g.drawImage(imageBufferedImage, 0, 0, poster.getImgW().intValue(), poster.getImgH().intValue(), null);
/*     */ 
/*     */     
/* 152 */     Color colorByHex = Color.decode(poster.getQrColor());
/* 153 */     int color_r = colorByHex.getRed();
/* 154 */     int color_g = colorByHex.getGreen();
/* 155 */     int color_b = colorByHex.getBlue();
/*     */     
/* 157 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*     */     
/* 159 */     if (member.getInvitationCode() == null) {
/* 160 */       String randomStringUpper = RandomUtil.randomStringUpper(10);
/* 161 */       member.setInvitationCode(randomStringUpper);
/* 162 */       this.memberService.saveOrUpdate(member);
/*     */     } 
/*     */     
/* 165 */     String invitation_code = member.getInvitationCode();
/*     */ 
/*     */ 
/*     */     
/*     */     try {
/* 170 */       byte[] qrCodeImage = QRCodeGenerator.getQRCodeImage(systemConfig.getServiceUrl() + "/open/register?invitation_code=" + invitation_code);
/* 171 */       BufferedImage qrCodeImageBuffered = ImageConverter.byteToBufferedImage(qrCodeImage);
/* 172 */       g.drawImage(qrCodeImageBuffered, poster.getQrX().intValue(), poster.getQrY().intValue(), poster.getQrW().intValue(), poster.getQrH().intValue(), null);
/* 173 */       g.dispose();
/*     */     }
/* 175 */     catch (WriterException e) {
/* 176 */       e.printStackTrace();
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 181 */     ByteArrayOutputStream bos = new ByteArrayOutputStream();
/*     */     
/* 183 */     ImageIO.write(image, "JPEG", bos);
/*     */     
/* 185 */     byte[] buf = bos.toByteArray();
/* 186 */     response.setContentLength(buf.length);
/* 187 */     sos.write(buf);
/* 188 */     bos.close();
/* 189 */     sos.close();
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @GetMapping(value = {"/generateQRCode"}, produces = {"image/png"})
/*     */   public ResponseEntity<byte[]> generateQRCode(@RequestParam("text") String text, @RequestParam(required = false, defaultValue = "0") Integer color_r, @RequestParam(required = false, defaultValue = "0") Integer color_g, @RequestParam(required = false, defaultValue = "0") Integer color_b) {
/* 200 */     Color color = new Color(color_r.intValue(), color_g.intValue(), color_b.intValue());
/*     */     
/*     */     try {
/* 203 */       byte[] qrCodeImage = QRCodeGeneratorWithColor.generateColoredQRCodeImage(text, color, Color.WHITE);
/* 204 */       HttpHeaders headers = new HttpHeaders();
/* 205 */       headers.setContentType(MediaType.IMAGE_PNG);
/* 206 */       return new ResponseEntity(qrCodeImage, (MultiValueMap)headers, HttpStatus.OK);
/* 207 */     } catch (Exception e) {
/*     */       
/* 209 */       return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
/*     */     } 
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public static BufferedImage makeRoundedCorner(BufferedImage image, int cornerRadius) {
/* 222 */     int w = image.getWidth();
/* 223 */     int h = image.getHeight();
/* 224 */     BufferedImage output = new BufferedImage(w, h, 2);
/*     */ 
/*     */     
/* 227 */     Graphics2D g2 = output.createGraphics();
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 234 */     g2.setComposite(AlphaComposite.Src);
/* 235 */     g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
/*     */     
/* 237 */     g2.setColor(Color.WHITE);
/* 238 */     g2.fill(new RoundRectangle2D.Float(0.0F, 0.0F, w, h, cornerRadius, cornerRadius));
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 243 */     g2.setComposite(AlphaComposite.SrcAtop);
/* 244 */     g2.drawImage(image, 0, 0, (ImageObserver)null);
/*     */     
/* 246 */     g2.dispose();
/*     */     
/* 248 */     return output;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\DrawController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */