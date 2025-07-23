/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.*;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/*    */
/*    */
@TableName("grade")
/*    */ public class Grade implements Serializable {
    /*    */
    @TableId(type = IdType.AUTO)
    /*    */ private Integer id;
    /*    */   private String merchant;
    /*    */   private String name;
    /*    */   private Integer sort;
    /*    */   private Double price;
    /*    */   private Double gain;
    /*    */   private Integer total;

    /*    */
    /* 14 */
    public void setId(Integer id) {
        this.id = id;
    }

    private Integer state;
    private Double present;
    private Double directSpread;
    private Double indirectSpread;
    private Integer period;
    private String periodRefer;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date creatTime;
    private static final long serialVersionUID = 1L;

    public void setMerchant(String merchant) {
        this.merchant = merchant;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public void setGain(Double gain) {
        this.gain = gain;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public void setState(Integer state) {
        this.state = state;
    }

    public void setPresent(Double present) {
        this.present = present;
    }

    public void setDirectSpread(Double directSpread) {
        this.directSpread = directSpread;
    }

    public void setIndirectSpread(Double indirectSpread) {
        this.indirectSpread = indirectSpread;
    }

    public void setPeriod(Integer period) {
        this.period = period;
    }

    public void setPeriodRefer(String periodRefer) {
        this.periodRefer = periodRefer;
    }

    public void setCreatTime(Date creatTime) {
        this.creatTime = creatTime;
    }

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.Grade)) return false;
        com.bss.entity.Grade other = (com.bss.entity.Grade) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
        Object this$merchant = getMerchant(), other$merchant = other.getMerchant();
        if (!Objects.equals(this$merchant, other$merchant)) return false;
        Object this$name = getName(), other$name = other.getName();
        if (!Objects.equals(this$name, other$name)) return false;
        Object this$sort = getSort(), other$sort = other.getSort();
        if (!Objects.equals(this$sort, other$sort)) return false;
        Object this$price = getPrice(), other$price = other.getPrice();
        if (!Objects.equals(this$price, other$price)) return false;
        Object this$gain = getGain(), other$gain = other.getGain();
        if (!Objects.equals(this$gain, other$gain)) return false;
        Object this$total = getTotal(), other$total = other.getTotal();
        if (!Objects.equals(this$total, other$total)) return false;
        Object this$state = getState(), other$state = other.getState();
        if (!Objects.equals(this$state, other$state)) return false;
        Object this$present = getPresent(), other$present = other.getPresent();
        if (!Objects.equals(this$present, other$present)) return false;
        Object this$directSpread = getDirectSpread(), other$directSpread = other.getDirectSpread();
        if (!Objects.equals(this$directSpread, other$directSpread))
            return false;
        Object this$indirectSpread = getIndirectSpread(), other$indirectSpread = other.getIndirectSpread();
        if (!Objects.equals(this$indirectSpread, other$indirectSpread))
            return false;
        Object this$period = getPeriod(), other$period = other.getPeriod();
        if (!Objects.equals(this$period, other$period)) return false;
        Object this$periodRefer = getPeriodRefer(), other$periodRefer = other.getPeriodRefer();
        if (!Objects.equals(this$periodRefer, other$periodRefer))
            return false;
        Object this$creatTime = getCreatTime(), other$creatTime = other.getCreatTime();
        return !(!Objects.equals(this$creatTime, other$creatTime));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.Grade;
    }


    public String toString() {
        return "Grade(id=" + getId() + ", merchant=" + getMerchant() + ", name=" + getName() + ", sort=" + getSort() + ", price=" + getPrice() + ", gain=" + getGain() + ", total=" + getTotal() + ", state=" + getState() + ", present=" + getPresent() + ", directSpread=" + getDirectSpread() + ", indirectSpread=" + getIndirectSpread() + ", period=" + getPeriod() + ", periodRefer=" + getPeriodRefer() + ", creatTime=" + getCreatTime() + ")";
    }

    /*    */
    /*    */
    public Integer getId() {
        /* 17 */
        return this.id;
        /*    */
    }

    public String getMerchant() {
        /* 19 */
        return this.merchant;
        /*    */
    }

    public String getName() {
        /* 21 */
        return this.name;
        /*    */
    }

    public Integer getSort() {
        /* 23 */
        return this.sort;
        /*    */
    }

    public Double getPrice() {
        /* 25 */
        return this.price;
        /*    */
    }

    public Double getGain() {
        /* 27 */
        return this.gain;
        /*    */
    }

    public Integer getTotal() {
        /* 29 */
        return this.total;
        /*    */
    }

    public Integer getState() {
        /* 31 */
        return this.state;
        /*    */
    }

    public Double getPresent() {
        /* 33 */
        return this.present;
        /*    */
    }

    public Double getDirectSpread() {
        /* 35 */
        return this.directSpread;
        /*    */
    }

    public Double getIndirectSpread() {
        /* 37 */
        return this.indirectSpread;
        /*    */
    }

    public Integer getPeriod() {
        /* 39 */
        return this.period;
        /*    */
    }

    public String getPeriodRefer() {
        /* 41 */
        return this.periodRefer;
        /*    */
    }

    /*    */
    public Date getCreatTime() {
        /* 44 */
        return this.creatTime;
        /*    */
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\Grade.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */