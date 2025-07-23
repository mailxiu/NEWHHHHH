/*    */
package com.bss.entity;

import com.baomidou.mybatisplus.annotation.TableName;

import java.io.Serializable;
import java.util.Objects;

/*    */
/*    */
@TableName("grade")
/*    */ public class GradeVo implements Serializable {
    private static final long serialVersionUID = 1L;
    /*    */   private Integer id;
    /*    */   private String name;
    /*    */   private Integer sort;
    /*    */   private Double price;
    /*    */   private Double gain;
    /*    */   private Integer total;
    private Double present;
    private Double directSpread;
    private Double indirectSpread;
    private Integer period;
    private String periodRefer;

    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof com.bss.entity.GradeVo)) return false;
        com.bss.entity.GradeVo other = (com.bss.entity.GradeVo) o;
        if (!other.canEqual(this)) return false;
        Object this$id = getId(), other$id = other.getId();
        if (!Objects.equals(this$id, other$id)) return false;
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
        return !(!Objects.equals(this$periodRefer, other$periodRefer));
    }

    protected boolean canEqual(Object other) {
        return other instanceof com.bss.entity.GradeVo;
    }


    public String toString() {
        return "GradeVo(id=" + getId() + ", name=" + getName() + ", sort=" + getSort() + ", price=" + getPrice() + ", gain=" + getGain() + ", total=" + getTotal() + ", present=" + getPresent() + ", directSpread=" + getDirectSpread() + ", indirectSpread=" + getIndirectSpread() + ", period=" + getPeriod() + ", periodRefer=" + getPeriodRefer() + ")";
    }

    /*    */
    public Integer getId() {
        /* 14 */
        return this.id;
        /*    */
    }

    /*    */
    /* 12 */
    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        /* 16 */
        return this.name;
        /*    */
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getSort() {
        /* 18 */
        return this.sort;
        /*    */
    }

    public void setSort(Integer sort) {
        this.sort = sort;
    }

    public Double getPrice() {
        /* 20 */
        return this.price;
        /*    */
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public Double getGain() {
        /* 22 */
        return this.gain;
        /*    */
    }

    public void setGain(Double gain) {
        this.gain = gain;
    }

    public Integer getTotal() {
        /* 24 */
        return this.total;
        /*    */
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public Double getPresent() {
        /* 26 */
        return this.present;
        /*    */
    }

    public void setPresent(Double present) {
        this.present = present;
    }

    public Double getDirectSpread() {
        /* 28 */
        return this.directSpread;
        /*    */
    }

    public void setDirectSpread(Double directSpread) {
        this.directSpread = directSpread;
    }

    public Double getIndirectSpread() {
        /* 30 */
        return this.indirectSpread;
        /*    */
    }

    public void setIndirectSpread(Double indirectSpread) {
        this.indirectSpread = indirectSpread;
    }

    public Integer getPeriod() {
        /* 32 */
        return this.period;
        /*    */
    }

    public void setPeriod(Integer period) {
        this.period = period;
    }

    public String getPeriodRefer() {
        /* 34 */
        return this.periodRefer;
        /*    */
    }

    public void setPeriodRefer(String periodRefer) {
        this.periodRefer = periodRefer;
    }
    /*    */
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\entity\GradeVo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */