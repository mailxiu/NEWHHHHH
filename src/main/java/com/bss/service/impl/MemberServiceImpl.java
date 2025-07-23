/*     */ package com.bss.service.impl;
/*     */ 
/*     */ import com.baomidou.mybatisplus.core.conditions.Wrapper;
/*     */ import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
/*     */ import com.baomidou.mybatisplus.extension.api.R;
/*     */ import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
/*     */ import com.bss.entity.Deposit;
/*     */ import com.bss.entity.Dividend;
/*     */ import com.bss.entity.Grade;
/*     */ import com.bss.entity.Member;
/*     */ import com.bss.entity.MemberDTO;
/*     */ import com.bss.entity.Settlement;
/*     */ import com.bss.mapper.MemberMapper;
/*     */ import com.bss.service.DividendService;
/*     */ import com.bss.service.GradeService;
/*     */ import com.bss.service.MemberService;
/*     */ import com.bss.service.SettlementService;
/*     */
/*     */ import java.math.BigDecimal;
/*     */ import java.util.Calendar;
/*     */ import java.util.Date;
/*     */ import java.util.List;
/*     */ import javax.annotation.Resource;
/*     */ import org.springframework.stereotype.Service;
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
/*     */ @Service
/*     */ public class MemberServiceImpl
/*     */   extends ServiceImpl<MemberMapper, Member>
/*     */   implements MemberService
/*     */ {
/*     */   @Resource
/*     */   private MemberMapper memberMapper;
/*     */   @Resource
/*     */   private GradeService gradeService;
/*     */   @Resource
/*     */   private DepositServiceImpl depositService;
/*     */   @Resource
/*     */   private DividendService dividendService;
/*     */   @Resource
/*     */   private SettlementService settlementService;
/*     */   
/*     */   public List<MemberDTO> getInvitationMember(Long uid, Integer partner, Integer pageIndex, Integer pageSize) {
/*  54 */     Integer offset = Integer.valueOf((pageIndex.intValue() - 1) * pageSize.intValue());
/*  55 */     return this.memberMapper.getInvitationMember(uid, partner, offset, pageSize);
/*     */   }
/*     */   
/*     */   public List<MemberDTO> getInvitationMemberCount(Long uid, Integer partner) {
/*  59 */     return this.memberMapper.getInvitationMemberCount(uid, partner);
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
/*     */   public R upgrade(String uid, Integer partner) {
/*  72 */     Member member = (Member)getOne((Wrapper)(new QueryWrapper()).eq("uid", uid));
/*     */     
/*  74 */     Grade grade = (Grade)this.gradeService.getOne((Wrapper)(new QueryWrapper()).eq("sort", partner));
/*     */     
/*  76 */     if (member == null) {
/*  77 */       return R.failed("用户不存在");
/*     */     }
/*     */     
/*  80 */     if (grade == null) {
/*  81 */       return R.failed("等级不存在");
/*     */     }
/*     */     
/*  84 */     if (partner.intValue() == 1) {
/*  85 */       member.setPartner(partner);
/*  86 */       member.setExpireTime(null);
/*     */       
/*  88 */       saveOrUpdate(member);
/*     */       
/*  90 */       return R.ok(Boolean.valueOf(true));
/*     */     } 
/*     */ 
/*     */     
/*  94 */     if (member.getExpireTime() == null) {
/*  95 */       Calendar calendar = Calendar.getInstance();
/*     */       
/*  97 */       calendar.add(5, grade.getPeriod().intValue());
/*     */       
/*  99 */       member.setExpireTime(calendar.getTime());
/*     */     }
/*     */     else {
/*     */       
/* 103 */       Date expireTime = member.getExpireTime();
/*     */       
/* 105 */       if (expireTime.after(new Date())) {
/*     */         
/* 107 */         if (grade.getSort() == member.getPartner()) {
/*     */           
/* 109 */           Calendar calendar = Calendar.getInstance();
/*     */           
/* 111 */           calendar.setTime(member.getExpireTime());
/*     */           
/* 113 */           calendar.add(5, grade.getPeriod().intValue());
/*     */           
/* 115 */           member.setExpireTime(calendar.getTime());
/*     */         } else {
/*     */           
/* 118 */           Calendar calendar = Calendar.getInstance();
/*     */           
/* 120 */           calendar.add(5, grade.getPeriod().intValue());
/*     */           
/* 122 */           member.setExpireTime(calendar.getTime());
/*     */         }
/*     */       
/*     */       } else {
/*     */         
/* 127 */         Calendar calendar = Calendar.getInstance();
/*     */         
/* 129 */         calendar.add(5, grade.getPeriod().intValue());
/*     */         
/* 131 */         member.setExpireTime(calendar.getTime());
/*     */       } 
/*     */     } 
/*     */ 
/*     */     
/* 136 */     member.setPartner(partner);
/*     */     
/* 138 */     saveOrUpdate(member);
/*     */ 
/*     */ 
/*     */     
/* 142 */     Deposit deposit = (Deposit)this.depositService.getOne((Wrapper)(new QueryWrapper()).eq("uid", member.getUid()));
/*     */     
/* 144 */     if (deposit == null) {
/*     */       
/* 146 */       deposit = new Deposit();
/*     */       
/* 148 */       deposit.setId(Integer.valueOf(0));
/* 149 */       deposit.setUid(member.getUid());
/* 150 */       deposit.setMoney(new BigDecimal(grade.getPrice().toString()));
/* 151 */       deposit.setState(Boolean.valueOf(false));
/*     */       
/* 153 */       this.depositService.save(deposit);
/*     */     } 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */     
/* 164 */     Member direct_member = (Member)getOne((Wrapper)(new QueryWrapper()).eq("uid", member.getMid()));
/*     */     
/* 166 */     if (direct_member != null) {
/*     */       
/* 168 */       if (direct_member.getPartner().intValue() >= 1) {
/*     */ 
/*     */         
/* 171 */         Dividend dividend = (Dividend)this.dividendService.getOne((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("relation", "direct")).eq("request_grade", direct_member.getPartner())).eq("response_grade", member.getPartner()));
/*     */         
/* 173 */         if (dividend == null) {
/* 174 */           return R.failed("直推分佣：" + direct_member.getPartner() + "》" + member.getPartner() + "配置不存在");
/*     */         }
/*     */         
/* 177 */         Double direct_total = Double.valueOf(grade.getPrice().doubleValue() * dividend.getSpread().doubleValue());
/*     */         
/* 179 */         direct_member.setPoints(Double.valueOf(direct_member.getPoints().doubleValue() + direct_total.doubleValue()));
/*     */         
/* 181 */         Settlement settlement = new Settlement();
/* 182 */         settlement.setId(Integer.valueOf(0));
/* 183 */         settlement.setSid(member.getUid());
/* 184 */         settlement.setUid(direct_member.getUid());
/* 185 */         settlement.setType("升级分佣");
/* 186 */         settlement.setNotes("源自：直推下级" + member.getUid() + ",升级" + grade.getName());
/* 187 */         settlement.setTotal(direct_total);
/*     */         
/* 189 */         this.settlementService.save(settlement);
/*     */         
/* 191 */         saveOrUpdate(direct_member);
/*     */       } 
/*     */ 
/*     */       
/* 195 */       Member indirect_member = (Member)getOne((Wrapper)(new QueryWrapper()).eq("uid", direct_member.getMid()));
/*     */       
/* 197 */       if (indirect_member != null && indirect_member.getPartner().intValue() >= 2) {
/*     */         
/* 199 */         Dividend dividend = (Dividend)this.dividendService.getOne((Wrapper)((QueryWrapper)((QueryWrapper)(new QueryWrapper()).eq("relation", "indirect")).eq("request_grade", indirect_member.getPartner())).eq("response_grade", member.getPartner()));
/*     */         
/* 201 */         if (dividend == null) {
/* 202 */           return R.failed("间推分佣：" + indirect_member.getPartner() + "》" + member.getPartner() + "配置不存在");
/*     */         }
/*     */         
/* 205 */         Double indirect_total = Double.valueOf(grade.getPrice().doubleValue() * dividend.getSpread().doubleValue());
/*     */         
/* 207 */         indirect_member.setPoints(Double.valueOf(indirect_member.getPoints().doubleValue() + indirect_total.doubleValue()));
/*     */         
/* 209 */         Settlement settlement_one = new Settlement();
/* 210 */         settlement_one.setId(Integer.valueOf(0));
/* 211 */         settlement_one.setSid(member.getUid());
/* 212 */         settlement_one.setUid(indirect_member.getUid());
/* 213 */         settlement_one.setType("升级分佣");
/* 214 */         settlement_one.setNotes("源自：间推下级" + member.getUid() + ",升级" + grade.getName());
/* 215 */         settlement_one.setTotal(indirect_total);
/*     */         
/* 217 */         this.settlementService.save(settlement_one);
/*     */         
/* 219 */         saveOrUpdate(indirect_member);
/*     */       } 
/*     */     } 
/*     */ 
/*     */ 
/*     */     
/* 225 */     return R.ok(Boolean.valueOf(true));
/*     */   }
/*     */ }


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\service\impl\MemberServiceImpl.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */