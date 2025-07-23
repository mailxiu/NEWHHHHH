/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.*;
import com.bss.enmus.SceneEnum;

import java.io.Serializable;
import java.util.Date;

/*    */
@TableName("member")
/*    */ public class Member implements Serializable {
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    private String merchant;
    private String mid;
    /*    */   private String uid;
    /*    */   private String unionid;
    /*    */   private String openid;
    /*    */   private String name;
    /*    */   private String portrait;
    /*    */   private Double points;
    /*    */   private Integer partner;
    /*    */   private String phone;
    /*    */   private String alipayName;

    /*    */
    /* 15 */
    public void setId(Integer id) {
        this.id = id;
    }

    private String alipayAccount;
    private String wxPay;
    private String bankRealName;
    private String bankCardNumber;
    private String bankAccountName;
    private SceneEnum scene;
    private String invitationCode;
    private String state;
    private Date expireTime;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date updateTime;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;
    private static final long serialVersionUID = 1L;

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setMid(String mid) {
        this.mid = mid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public void setUnionid(String unionid) {
        this.unionid = unionid;
    }

    public void setOpenid(String openid) {
        this.openid = openid;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setPortrait(String portrait) {
        this.portrait = portrait;
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public void setPartner(Integer partner) {
        this.partner = partner;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public void setAlipayName(String alipayName) {
        this.alipayName = alipayName;
    }

    public void setAlipayAccount(String alipayAccount) {
        this.alipayAccount = alipayAccount;
    }

    public void setWxPay(String wxPay) {
        this.wxPay = wxPay;
    }

    public void setBankRealName(String bankRealName) {
        this.bankRealName = bankRealName;
    }

    public void setBankCardNumber(String bankCardNumber) {
        this.bankCardNumber = bankCardNumber;
    }

    public void setBankAccountName(String bankAccountName) {
        this.bankAccountName = bankAccountName;
    }

    public void setScene(SceneEnum scene) {
        this.scene = scene;
    }

    public void setInvitationCode(String invitationCode) {
        this.invitationCode = invitationCode;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setExpireTime(Date expireTime) {
        this.expireTime = expireTime;
    }

    public void setUpdateTime(Date updateTime) {
        this.updateTime = updateTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Member)) return false;
        com.bss.entity.Member other = (com.bss.entity.Member) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if ((this$id == null) ? (other$id != null) : !this$id.equals(other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if ((this$merchant == null) ? (other$merchant != null) : !this$merchant.equals(other$merchant)) return false;
        Object this$mid = getMid(), other$mid = other.getMid();
        if ((this$mid == null) ? (other$mid != null) : !this$mid.equals(other$mid)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if ((this$uid == null) ? (other$uid != null) : !this$uid.equals(other$uid)) return false;
        Object this$unionid = getUnionid(), other$unionid = other.getUnionid();
        if ((this$unionid == null) ? (other$unionid != null) : !this$unionid.equals(other$unionid)) return false;
        Object this$openid = getOpenid(), other$openid = other.getOpenid();
        if ((this$openid == null) ? (other$openid != null) : !this$openid.equals(other$openid)) return false;
        Object this$name = getName(), other$name = other.getName();
        if ((this$name == null) ? (other$name != null) : !this$name.equals(other$name)) return false;
        Object this$portrait = getPortrait(), other$portrait = other.getPortrait();
        if ((this$portrait == null) ? (other$portrait != null) : !this$portrait.equals(other$portrait)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if ((this$points == null) ? (other$points != null) : !this$points.equals(other$points)) return false;
        Object this$partner = getPartner(), other$partner = other.getPartner();
        if ((this$partner == null) ? (other$partner != null) : !this$partner.equals(other$partner)) return false;
        Object this$phone = getPhone(), other$phone = other.getPhone();
        if ((this$phone == null) ? (other$phone != null) : !this$phone.equals(other$phone)) return false;
        Object this$alipayName = getAlipayName(), other$alipayName = other.getAlipayName();
        if ((this$alipayName == null) ? (other$alipayName != null) : !this$alipayName.equals(other$alipayName))
            return false;
        Object this$alipayAccount = getAlipayAccount(), other$alipayAccount = other.getAlipayAccount();
        if ((this$alipayAccount == null) ? (other$alipayAccount != null) : !this$alipayAccount.equals(other$alipayAccount))
            return false;
        Object this$wxPay = getWxPay(), other$wxPay = other.getWxPay();
        if ((this$wxPay == null) ? (other$wxPay != null) : !this$wxPay.equals(other$wxPay)) return false;
        Object this$bankRealName = getBankRealName(), other$bankRealName = other.getBankRealName();
        if ((this$bankRealName == null) ? (other$bankRealName != null) : !this$bankRealName.equals(other$bankRealName))
            return false;
        Object this$bankCardNumber = getBankCardNumber(), other$bankCardNumber = other.getBankCardNumber();
        if ((this$bankCardNumber == null) ? (other$bankCardNumber != null) : !this$bankCardNumber.equals(other$bankCardNumber))
            return false;
        Object this$bankAccountName = getBankAccountName(), other$bankAccountName = other.getBankAccountName();
        if ((this$bankAccountName == null) ? (other$bankAccountName != null) : !this$bankAccountName.equals(other$bankAccountName))
            return false;
        Object this$scene = getScene(), other$scene = other.getScene();
        if ((this$scene == null) ? (other$scene != null) : !this$scene.equals(other$scene)) return false;
        Object this$invitationCode = getInvitationCode(), other$invitationCode = other.getInvitationCode();
        if ((this$invitationCode == null) ? (other$invitationCode != null) : !this$invitationCode.equals(other$invitationCode))
            return false;
        Object this$state = getState(), other$state = other.getState();
        if ((this$state == null) ? (other$state != null) : !this$state.equals(other$state)) return false;
        Object this$expireTime = getExpireTime(), other$expireTime = other.getExpireTime();
        if ((this$expireTime == null) ? (other$expireTime != null) : !this$expireTime.equals(other$expireTime))
            return false;
        Object this$updateTime = getUpdateTime(), other$updateTime = other.getUpdateTime();
        if ((this$updateTime == null) ? (other$updateTime != null) : !this$updateTime.equals(other$updateTime))
            return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        return !((this$createTime == null) ? (other$createTime != null) : !this$createTime.equals(other$createTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Member;
    }


    public String toString() {
        return "Member(id=" + getId() + ", merchant=" + getMerchant() + ", mid=" + getMid() + ", uid=" + getUid() + ", unionid=" + getUnionid() + ", openid=" + getOpenid() + ", name=" + getName() + ", portrait=" + getPortrait() + ", points=" + getPoints() + ", partner=" + getPartner() + ", phone=" + getPhone() + ", alipayName=" + getAlipayName() + ", alipayAccount=" + getAlipayAccount() + ", wxPay=" + getWxPay() + ", bankRealName=" + getBankRealName() + ", bankCardNumber=" + getBankCardNumber() + ", bankAccountName=" + getBankAccountName() + ", scene=" + getScene() + ", invitationCode=" + getInvitationCode() + ", state=" + getState() + ", expireTime=" + getExpireTime() + ", updateTime=" + getUpdateTime() + ", createTime=" + getCreateTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 18 */
        return this.id;
        /*    */
    }

    public String getMerchant() {
        /* 20 */
        return this.merchant;
        /*    */
    }

    public String getMid() {
        /* 22 */
        return this.mid;
        /*    */
    }

    public String getUid() {
        /* 24 */
        return this.uid;
        /*    */
    }

    public String getUnionid() {
        /* 26 */
        return this.unionid;
        /*    */
    }

    public String getOpenid() {
        /* 28 */
        return this.openid;
        /*    */
    }

    public String getName() {
        /* 30 */
        return this.name;
        /*    */
    }

    public String getPortrait() {
        /* 32 */
        return this.portrait;
        /*    */
    }

    public Double getPoints() {
        /* 34 */
        return this.points;
        /*    */
    }

    public Integer getPartner() {
        /* 36 */
        return this.partner;
        /*    */
    }

    public String getPhone() {
        /* 38 */
        return this.phone;
        /*    */
    }

    public String getAlipayName() {
        /* 40 */
        return this.alipayName;
        /*    */
    }

    public String getAlipayAccount() {
        /* 42 */
        return this.alipayAccount;
        /*    */
    }

    public String getWxPay() {
        /* 44 */
        return this.wxPay;
        /*    */
    }

    public String getBankRealName() {
        /* 46 */
        return this.bankRealName;
        /*    */
    }

    public String getBankCardNumber() {
        /* 48 */
        return this.bankCardNumber;
        /*    */
    }

    public String getBankAccountName() {
        /* 50 */
        return this.bankAccountName;
        /*    */
    }

    public SceneEnum getScene() {
        /* 52 */
        return this.scene;
        /*    */
    }

    public String getInvitationCode() {
        /* 54 */
        return this.invitationCode;
        /*    */
    }

    public String getState() {
        /* 56 */
        return this.state;
        /*    */
    }

    public Date getExpireTime() {
        /* 58 */
        return this.expireTime;
        /*    */
    }

    /*    */
    public Date getUpdateTime() {
        /* 61 */
        return this.updateTime;
        /*    */
    }

    /*    */
    public Date getCreateTime() {
        /* 64 */
        return this.createTime;
        /*    */
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Member.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */