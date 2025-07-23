/*    */
package com.bss.entity;

import com.alibaba.excel.annotation.ExcelIgnore;
import com.alibaba.excel.annotation.ExcelProperty;
import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
@TableName("stock")
/*    */ public class StockNum implements Serializable {
    private static final long serialVersionUID = 1L;
    @ExcelIgnore
    /*    */ private Object id;
    @ExcelProperty({"商户ID"})
    /*    */ private String merchant;
    @ExcelProperty({"订单ID"})
    /*    */ private String oid;
    @ExcelProperty({"用户ID"})
    /*    */ private String uid;
    @ExcelIgnore
    /*    */ private Integer cid;
    /*    */
    @ExcelProperty({"名称"})
    /*    */ private String name;
    /*    */
    @ExcelIgnore
    /*    */ private String image;
    @ExcelProperty({"积分"})
    private Double points;
    @ExcelProperty({"条形码"})
    private String code;
    @ExcelProperty({"二维码"})
    private String qrCode;
    @ExcelProperty({"验证码"})
    private String checkCode;
    @ExcelProperty({"状态"})
    private String state;
    @ExcelProperty({"扫入时间"})
    private String createTime;
    private Integer num;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.StockNum)) return false;
        com.bss.entity.StockNum other = (com.bss.entity.StockNum) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$oid = getOid(), other$oid = other.getOid();
        if (!Objects.equals(this$oid, other$oid)) return false;
        Object this$uid = getUid(), other$uid = other.getUid();
        if (!Objects.equals(this$uid, other$uid)) return false;
        Object this$cid = getCid(), other$cid = other.getCid();
        if (!Objects.equals(this$cid, other$cid)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$image = getImage(), other$image = other.getImage();
        if (!Objects.equals(this$image, other$image)) return false;
        Object this$points = getPoints(), other$points = other.getPoints();
        if (!Objects.equals(this$points, other$points)) return false;
        Object this$code = getCode(), other$code = other.getCode();
        if (!Objects.equals(this$code, other$code)) return false;
        Object this$qrCode = getQrCode(), other$qrCode = other.getQrCode();
        if (!Objects.equals(this$qrCode, other$qrCode)) return false;
        Object this$checkCode = getCheckCode(), other$checkCode = other.getCheckCode();
        if (!Objects.equals(this$checkCode, other$checkCode))
            return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$createTime = getCreateTime(), other$createTime = other.getCreateTime();
        if (!Objects.equals(this$createTime, other$createTime))
            return false;
        Object this$num = getNum(), other$num = other.getNum();
        return !(!Objects.equals(this$num, other$num));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.StockNum;
    }


    public String toString() {
        return "StockNum(id=" + getId() + ", merchant=" + getMerchant() + ", oid=" + getOid() + ", uid=" + getUid() + ", cid=" + getCid() + ", name=" + getName() + ", image=" + getImage() + ", points=" + getPoints() + ", code=" + getCode() + ", qrCode=" + getQrCode() + ", checkCode=" + getCheckCode() + ", state=" + getState() + ", createTime=" + getCreateTime() + ", num=" + getNum() + ")";
    }

    /*    */
    /*    */
    public Object getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    /*    */
    /* 14 */
    public void setId(Object id) {
        this.id = id;
    }

    public String getMerchant() {
        /* 19 */
        return this.merchant;
        /*    */
    }

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public String getOid() {
        /* 21 */
        return this.oid;
        /*    */
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getUid() {
        /* 23 */
        return this.uid;
        /*    */
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public Integer getCid() {
        /* 25 */
        return this.cid;
        /*    */
    }

    public void setCid(Integer cid) {
        this.cid = cid;
    }

    public String getName() {
        /* 27 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImage() {
        /* 29 */
        return this.image;
        /*    */
    }

    public void setImage(String image) {
        this.image = image;
    }

    public Double getPoints() {
        /* 31 */
        return this.points;
        /*    */
    }

    public void setPoints(Double points) {
        this.points = points;
    }

    public String getCode() {
        /* 33 */
        return this.code;
        /*    */
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getQrCode() {
        /* 35 */
        return this.qrCode;
        /*    */
    }

    public void setQrCode(String qrCode) {
        this.qrCode = qrCode;
    }

    public String getCheckCode() {
        /* 37 */
        return this.checkCode;
        /*    */
    }

    public void setCheckCode(String checkCode) {
        this.checkCode = checkCode;
    }

    public String getState() {
        /* 39 */
        return this.state;
        /*    */
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCreateTime() {
        /* 41 */
        return this.createTime;
        /*    */
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }

    public Integer getNum() {
        /* 43 */
        return this.num;
        /*    */
    }

    public void setNum(Integer num) {
        this.num = num;
    }
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\StockNum.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */