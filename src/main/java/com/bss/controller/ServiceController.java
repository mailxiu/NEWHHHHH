/*     */ package com.bss.controller;
/*     */ import cn.hutool.core.util.RandomUtil;
import com.alibaba.fastjson.JSON;
/*     */ import com.alibaba.fastjson.JSONObject;
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.bss.entity.AppletConfig;
/*     */ import com.bss.entity.Member;
import com.bss.service.impl.AppletConfigServiceImpl;
/*     */ import com.bss.service.impl.MemberServiceImpl;
import com.bss.utils.R;
/*     */ import java.awt.image.BufferedImage;
/*     */ import java.io.ByteArrayInputStream;
/*     */ import java.io.ByteArrayOutputStream;
/*     */ import java.io.IOException;
/*     */ import java.io.InputStream;
import org.apache.shiro.mgt.SecurityManager;
/*     */ import java.io.OutputStream;
/*     */ import java.util.HashMap;
/*     */ import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
/*     */ import javax.annotation.Resource;
/*     */ import javax.imageio.ImageIO;
/*     */ import javax.servlet.ServletOutputStream;
/*     */ import javax.servlet.http.HttpServletResponse;
/*     */ import org.slf4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
/*     */ import org.springframework.http.HttpHeaders;
/*     */ import org.springframework.http.HttpMethod;
/*     */ import org.springframework.http.MediaType;
/*     */ import org.springframework.http.ResponseEntity;
/*     */ import org.springframework.util.LinkedMultiValueMap;
/*     */ import org.springframework.util.MultiValueMap;
/*     */ import org.springframework.web.bind.annotation.*;
/*     */
/*     */
/*     */
import org.springframework.web.client.RestTemplate;
/*     */ import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
/*     */
/*     */ @RequestMapping({"/service"})
/*     */ @RestController
/*     */ public class ServiceController {
/*  40 */   private static final Logger log = LoggerFactory.getLogger(com.bss.controller.ServiceController.class);
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private AppletConfigServiceImpl appletConfigService;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private SecurityManager securityManager;
/*     */ 
/*     */   
/*     */   @Resource
/*     */   private MemberServiceImpl memberService;
/*     */ 
/*     */   
/*  55 */   private final ExecutorService executor = Executors.newFixedThreadPool(5);
/*     */ 
/*     */   
/*     */   @GetMapping(value = {"/stream"}, produces = {"text/event-stream"})
/*     */   public SseEmitter handleSse(String barCode, Double passRate, Long base) {
/*  60 */     log.info("自动核销计划：编码：{},通过率：{},核销基数：{}", new Object[] { barCode, passRate, base });
/*     */ 
/*     */     
/*  63 */     SecurityUtils.setSecurityManager(this.securityManager);
/*     */     
/*  65 */     SseEmitter emitter = new SseEmitter(Long.valueOf(-1L));
/*     */ 
/*     */     
/*  68 */     this.executor.submit(() -> {
/*     */           try {
/*     */             for (int i = 0; i < 10; i++) {
/*     */               if (i < 9) {
/*     */                 emitter.send(SseEmitter.event().id(String.valueOf(i)).name("event").data("Hello, world " + i));
/*     */               } else {
/*     */                 emitter.send(SseEmitter.event().id(String.valueOf(i)).name("close").data("Hello, world " + i));
/*     */               } 
/*     */ 
/*     */ 
/*     */ 
/*     */               
/*     */               Thread.sleep(1000L);
/*     */             } 
/*     */ 
/*     */ 
/*     */             
/*     */             emitter.complete();
/*  86 */           } catch (IOException|InterruptedException e) {
/*     */             emitter.completeWithError(e);
/*     */           } 
/*     */         });
/*     */     
/*  91 */     return emitter;
/*     */   }
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/getOpenid"})
/*     */   public R getOpenid(String appid, String code) {
/* 102 */     AppletConfig appletConfig = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 104 */     if (appletConfig == null) {
/* 105 */       return R.fail("小程序配置不存在");
/*     */     }
/*     */     
/* 108 */     String url = "https://api.weixin.qq.com/sns/jscode2session?grant_type=authorization_code&appid=" + appletConfig.getAppId() + "&secret=" + appletConfig.getSecret() + "&js_code=" + code;
/*     */     
/* 110 */     RestTemplate restTemplate = new RestTemplate();
/*     */     
/* 112 */     String object = (String)restTemplate.getForObject(url, String.class, new Object[0]);
/*     */     
/* 114 */     JSONObject data = JSON.parseObject(object);
/*     */ 
/*     */     
/* 117 */     Member member = (Member)this.memberService.getOne((Wrapper)(new QueryWrapper()).eq("openid", data.getString("openid")));
/*     */     
/* 119 */     if (member != null) {
/* 120 */       member.setUnionid(data.getString("unionid"));
/*     */       
/* 122 */       String randomStringUpper = RandomUtil.randomStringUpper(10);
/*     */       
/* 124 */       if (member.getInvitationCode() == null) {
/* 125 */         member.setInvitationCode(randomStringUpper);
/*     */       }
/* 127 */       this.memberService.saveOrUpdate(member);
/*     */     } 
/*     */     
/* 130 */     data.remove(data);
/*     */     
/* 132 */     return R.success(data);
/*     */   }
/*     */ 
/*     */   
/*     */   @RequestMapping({"/refresh_token"})
/*     */   public R refresh_token() {
/* 138 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)new QueryWrapper());
/*     */     
/* 140 */     if (applet == null) {
/* 141 */       return R.fail("小程序配置不存在");
/*     */     }
/*     */     
/* 144 */     String url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + applet.getAppId() + "&secret=" + applet.getSecret();
/*     */     
/* 146 */     MediaType type = MediaType.parseMediaType("application/x-www-form-urlencoded; charset=UTF-8");
/* 147 */     HttpHeaders headers = new HttpHeaders();
/* 148 */     headers.setContentType(type);
/*     */     
/* 150 */     HttpEntity<String> requestEntity = new HttpEntity(null, (MultiValueMap)headers);
/*     */     
/* 152 */     RestTemplate restTemplate = new RestTemplate();
/*     */     
/* 154 */     ResponseEntity<String> responseEntity = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class, new Object[0]);
/*     */     
/* 156 */     System.out.println((String)responseEntity.getBody());
/*     */     
/* 158 */     JSONObject data = JSONObject.parseObject((String)responseEntity.getBody());
/*     */     
/* 160 */     applet.setAccessToken(data.getString("access_token"));
/*     */     
/* 162 */     boolean update = this.appletConfigService.saveOrUpdate(applet);
/*     */     
/* 164 */     return R.success(Boolean.valueOf(update));
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
/*     */   @ResponseBody
/*     */   @RequestMapping({"/getPhoneNumber"})
/*     */   public String getPhoneNumber(String appid, String code) {
/* 178 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 180 */     String url = "https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=" + applet.getAccessToken();
/*     */ 
/*     */     
/* 183 */     HttpHeaders headers = new HttpHeaders();
/* 184 */     headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
/*     */     
/* 186 */     JSONObject jsonObject = new JSONObject();
/*     */     
/* 188 */     jsonObject.put("code", code);
/*     */     
/* 190 */     RestTemplate restTemplate = new RestTemplate();
/*     */     
/* 192 */     HttpEntity<String> request = new HttpEntity(jsonObject.toString(), (MultiValueMap)headers);
/*     */     
/* 194 */     String personResultAsJsonStr = (String)restTemplate.postForObject(url, request, String.class, new Object[0]);
/*     */     
/* 196 */     JSONObject object = JSON.parseObject(personResultAsJsonStr);
/*     */     
/* 198 */     log.info("获取小程序手机号返回：{}", object);
/*     */     
/* 200 */     return personResultAsJsonStr;
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
/*     */   
/*     */   @ResponseBody
/*     */   @RequestMapping({"/generateUrlLink"})
/*     */   public String generateUrlLink(String appid, String uid, String env_version) {
/* 215 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 217 */     String url = "https://api.weixin.qq.com/wxa/generate_urllink?access_token=" + applet.getAccessToken();
/*     */ 
/*     */     
/* 220 */     HttpHeaders headers = new HttpHeaders();
/* 221 */     headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
/*     */     
/* 223 */     JSONObject jsonObject = new JSONObject();
/*     */     
/* 225 */     jsonObject.put("path", "pages/index/index");
/*     */     
/* 227 */     jsonObject.put("query", "scene=" + uid);
/*     */     
/* 229 */     jsonObject.put("env_version", env_version);
/*     */     
/* 231 */     RestTemplate restTemplate = new RestTemplate();
/*     */     
/* 233 */     HttpEntity<String> request = new HttpEntity(jsonObject.toString(), (MultiValueMap)headers);
/*     */     
/* 235 */     String personResultAsJsonStr = (String)restTemplate.postForObject(url, request, String.class, new Object[0]);
/*     */     
/* 237 */     JSONObject object = JSON.parseObject(personResultAsJsonStr);
/*     */     
/* 239 */     if (!object.getInteger("errcode").equals(Integer.valueOf(0))) {
/*     */       
/* 241 */       log.info("傻逼微信Token推送错误：{}", object);
/*     */ 
/*     */       
/* 244 */       refresh_token();
/*     */     } 
/*     */     
/* 247 */     return personResultAsJsonStr;
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
/*     */   
/*     */   @ResponseBody
/*     */   @RequestMapping({"/queryUrlLink"})
/*     */   public String queryUrlLink(String appid, String url_link, Integer query_type) {
/* 262 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 264 */     String url = "https://api.weixin.qq.com/wxa/query_urllink?access_token=" + applet.getAccessToken();
/*     */ 
/*     */     
/* 267 */     HttpHeaders headers = new HttpHeaders();
/* 268 */     headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
/*     */     
/* 270 */     JSONObject jsonObject = new JSONObject();
/*     */     
/* 272 */     jsonObject.put("url_link", url_link);
/*     */     
/* 274 */     jsonObject.put("query_type", query_type);
/*     */     
/* 276 */     RestTemplate restTemplate = new RestTemplate();
/*     */     
/* 278 */     HttpEntity<String> request = new HttpEntity(jsonObject.toString(), (MultiValueMap)headers);
/*     */     
/* 280 */     String personResultAsJsonStr = (String)restTemplate.postForObject(url, request, String.class, new Object[0]);
/*     */     
/* 282 */     JSONObject object = JSON.parseObject(personResultAsJsonStr);
/*     */     
/* 284 */     log.info("查询加密URLLink返回：{}", object);
/*     */     
/* 286 */     return personResultAsJsonStr;
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
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/getUnlimitedQRCode"})
/*     */   public void getQRCode(String appid, String uid, @RequestParam(required = false, defaultValue = "0") Integer color_r, @RequestParam(required = false, defaultValue = "0") Integer color_g, @RequestParam(required = false, defaultValue = "0") Integer color_b, @RequestParam(required = false, defaultValue = "0") Boolean is_hyaline, String env_version, HttpServletResponse response) throws IOException {
/* 308 */     response.setContentType("image/png");
/* 309 */     ServletOutputStream sos = response.getOutputStream();
/*     */     
/* 311 */     response.setHeader("Pragma", "No-cache");
/* 312 */     response.setHeader("Cache-Control", "no-cache");
/* 313 */     response.setDateHeader("Expires", 0L);
/*     */     
/* 315 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 317 */     RestTemplate rest = new RestTemplate();
/* 318 */     InputStream inputStream = null;
/* 319 */     OutputStream outputStream = null;
/*     */     try {
/* 321 */       String url = "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=" + applet.getAccessToken();
/* 322 */       Map<String, Object> param = new HashMap<>();
/* 323 */       param.put("scene", uid);
/* 324 */       param.put("env_version", env_version);
/* 325 */       param.put("path", "pages/index/index");
/* 326 */       param.put("width", Integer.valueOf(800));
/* 327 */       param.put("auto_color", Boolean.valueOf(false));
/* 328 */       Map<String, Object> line_color = new HashMap<>();
/* 329 */       line_color.put("r", color_r);
/* 330 */       line_color.put("g", color_g);
/* 331 */       line_color.put("b", color_b);
/* 332 */       param.put("line_color", line_color);
/* 333 */       param.put("is_hyaline", is_hyaline);
/* 334 */       LinkedMultiValueMap linkedMultiValueMap = new LinkedMultiValueMap();
/* 335 */       HttpEntity requestEntity = new HttpEntity(param, (MultiValueMap)linkedMultiValueMap);
/*     */       
/* 337 */       ResponseEntity<byte[]> entity = rest.exchange(url, HttpMethod.POST, requestEntity, byte[].class, new Object[0]);
/*     */       
/* 339 */       byte[] result = (byte[])entity.getBody();
/*     */       
/* 341 */       HttpHeaders httpHeaders = entity.getHeaders();
/*     */       
/* 343 */       String type = httpHeaders.getFirst("Content-type");
/*     */       
/* 345 */       if (!type.equals("image/jpeg")) {
/* 346 */         System.out.println(new String(result, "UTF-8"));
/*     */       }
/*     */       
/* 349 */       inputStream = new ByteArrayInputStream(result);
/*     */       
/* 351 */       BufferedImage image = ImageIO.read(inputStream);
/*     */ 
/*     */       
/* 354 */       ByteArrayOutputStream bos = new ByteArrayOutputStream();
/*     */       
/* 356 */       ImageIO.write(image, "PNG", bos);
/*     */       
/* 358 */       byte[] buf = bos.toByteArray();
/* 359 */       response.setContentLength(buf.length);
/* 360 */       sos.write(buf);
/* 361 */       bos.close();
/* 362 */       sos.close();
/*     */     }
/* 364 */     catch (Exception e) {
/* 365 */       System.out.println("调用小程序生成微信永久小程序码URL接口异常");
/*     */     } finally {
/* 367 */       if (inputStream != null) {
/*     */         try {
/* 369 */           inputStream.close();
/* 370 */         } catch (IOException e) {
/* 371 */           e.printStackTrace();
/*     */         } 
/*     */       }
/* 374 */       if (outputStream != null) {
/*     */         try {
/* 376 */           outputStream.close();
/* 377 */         } catch (IOException e) {
/* 378 */           e.printStackTrace();
/*     */         } 
/*     */       }
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
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   @RequestMapping({"/getUnlimitedQRCode_v2"})
/*     */   public void getQRCodev2(String appid, String uid, @RequestParam(required = false, defaultValue = "0") Integer color_r, @RequestParam(required = false, defaultValue = "0") Integer color_g, @RequestParam(required = false, defaultValue = "0") Integer color_b, @RequestParam(required = false, defaultValue = "0") Boolean is_hyaline, String env_version, HttpServletResponse response) throws IOException {
/* 403 */     response.setContentType("image/png");
/* 404 */     ServletOutputStream sos = response.getOutputStream();
/*     */     
/* 406 */     response.setHeader("Pragma", "No-cache");
/* 407 */     response.setHeader("Cache-Control", "no-cache");
/* 408 */     response.setDateHeader("Expires", 0L);
/*     */     
/* 410 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 412 */     RestTemplate rest = new RestTemplate();
/* 413 */     InputStream inputStream = null;
/* 414 */     OutputStream outputStream = null;
/*     */     try {
/* 416 */       String url = "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=" + applet.getAccessToken();
/* 417 */       Map<String, Object> param = new HashMap<>();
/* 418 */       param.put("scene", uid);
/* 419 */       param.put("env_version", env_version);
/* 420 */       param.put("path", "pages/index/index");
/* 421 */       param.put("width", Integer.valueOf(800));
/* 422 */       param.put("auto_color", Boolean.valueOf(false));
/* 423 */       Map<String, Object> line_color = new HashMap<>();
/* 424 */       line_color.put("r", color_r);
/* 425 */       line_color.put("g", color_g);
/* 426 */       line_color.put("b", color_b);
/* 427 */       param.put("line_color", line_color);
/* 428 */       param.put("is_hyaline", is_hyaline);
/* 429 */       LinkedMultiValueMap linkedMultiValueMap = new LinkedMultiValueMap();
/* 430 */       HttpEntity requestEntity = new HttpEntity(param, (MultiValueMap)linkedMultiValueMap);
/*     */       
/* 432 */       ResponseEntity<byte[]> entity = rest.exchange(url, HttpMethod.POST, requestEntity, byte[].class, new Object[0]);
/*     */       
/* 434 */       byte[] result = (byte[])entity.getBody();
/*     */       
/* 436 */       HttpHeaders httpHeaders = entity.getHeaders();
/*     */       
/* 438 */       String type = httpHeaders.getFirst("Content-type");
/*     */       
/* 440 */       if (!type.equals("image/jpeg")) {
/* 441 */         System.out.println(new String(result, "UTF-8"));
/*     */       }
/*     */       
/* 444 */       inputStream = new ByteArrayInputStream(result);
/*     */       
/* 446 */       BufferedImage te = ImageIO.read(inputStream);
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */       
/* 464 */       ByteArrayOutputStream bos = new ByteArrayOutputStream();
/*     */       
/* 466 */       ImageIO.write(te, "PNG", bos);
/*     */       
/* 468 */       byte[] buf = bos.toByteArray();
/* 469 */       response.setContentLength(buf.length);
/* 470 */       sos.write(buf);
/* 471 */       bos.close();
/* 472 */       sos.close();
/*     */     }
/* 474 */     catch (Exception e) {
/* 475 */       System.out.println("调用小程序生成微信永久小程序码URL接口异常");
/*     */     } finally {
/* 477 */       if (inputStream != null) {
/*     */         try {
/* 479 */           inputStream.close();
/* 480 */         } catch (IOException e) {
/* 481 */           e.printStackTrace();
/*     */         } 
/*     */       }
/* 484 */       if (outputStream != null) {
/*     */         try {
/* 486 */           outputStream.close();
/* 487 */         } catch (IOException e) {
/* 488 */           e.printStackTrace();
/*     */         } 
/*     */       }
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
/*     */ 
/*     */ 
/*     */   
/*     */   @ResponseBody
/*     */   @PostMapping({"/getUserPortrait"})
/*     */   public String getUserPortrait(String appid, String begin_date, String end_date) {
/* 508 */     AppletConfig applet = (AppletConfig)this.appletConfigService.getOne((Wrapper)(new QueryWrapper()).eq("app_id", appid));
/*     */     
/* 510 */     String url = "https://api.weixin.qq.com/datacube/getweanalysisappiduserportrait?access_token=" + applet.getAccessToken();
/*     */ 
/*     */     
/* 513 */     HttpHeaders headers = new HttpHeaders();
/* 514 */     headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
/*     */     
/* 516 */     JSONObject jsonObject = new JSONObject();
/*     */     
/* 518 */     jsonObject.put("begin_date", begin_date);
/*     */     
/* 520 */     jsonObject.put("end_date", end_date);
/*     */     
/* 522 */     RestTemplate restTemplate = new RestTemplate();
/*     */     
/* 524 */     HttpEntity<String> request = new HttpEntity(jsonObject.toString(), (MultiValueMap)headers);
/*     */     
/* 526 */     String personResultAsJsonStr = (String)restTemplate.postForObject(url, request, String.class, new Object[0]);
/*     */     
/* 528 */     JSONObject object = JSON.parseObject(personResultAsJsonStr);
/*     */     
/* 530 */     log.info("查询获取用户小程序访问分布数据返回：{}", object);
/*     */     
/* 532 */     return personResultAsJsonStr;
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\controller\ServiceController.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */